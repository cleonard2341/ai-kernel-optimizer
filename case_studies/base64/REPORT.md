# Case Study: Base64 Decode Kernel

## Target
**Domain:** Encoding / serialization
**Function:** Base64 decode — convert base64-encoded ASCII to raw bytes
**Why this kernel:** Base64 is ubiquitous in web APIs (JWT tokens, data URIs, email attachments, binary-over-JSON). Every decode is a pure computational kernel: ASCII bytes in → raw bytes out. No I/O, no allocation, no global state.

## Why GCC Can't Vectorize This

The scalar implementation uses a 256-byte lookup table (LUT) to convert each ASCII character to its 6-bit value. GCC -O3 produces 46 instructions / 145 bytes — a tight scalar loop, but fundamentally limited because:

1. **Gather pattern:** 4 data-dependent table lookups per iteration (`b64_lut[src[i]]`). The addresses depend on the input data, so GCC cannot replace them with SIMD operations.
2. **4:3 ratio:** 4 input bytes produce 3 output bytes, preventing simple lane-parallel vectorization.
3. **Bit packing:** The shift-and-OR pattern to merge 4×6-bit values into 3×8-bit bytes doesn't map to any GCC autovectorization idiom.

## AI Strategy: SSSE3 Table-Free Vectorized Lookup

Process 16 input bytes → 12 output bytes per iteration, with **zero table lookups**:

### Step 1: ASCII → 6-bit values via `pshufb`

Instead of a 256-byte LUT, exploit the structure of the base64 alphabet. The 64 valid characters fall into 6 groups by high nibble:

| High nibble | Characters | Offset to 6-bit value |
|-------------|------------|-----------------------|
| 2 | `+` (0x2B) | +19 |
| 2 | `/` (0x2F) | +16 (corrected separately) |
| 3 | `0`-`9` | +4 |
| 4 | `A`-`O` | -65 |
| 5 | `P`-`Z` | -65 |
| 6 | `a`-`o` | -71 |
| 7 | `p`-`z` | -71 |

- Extract high nibble: `psrlw` + `pand 0x0F`
- Lookup offset by high nibble: `pshufb` with 16-byte LUT → 1 instruction replaces 16 table lookups
- Correct for `/` (shares nibble 2 with `+`): `pcmpeqb` + `pand` to subtract 3
- Apply: `paddb` × 2

### Step 2: Pack 4×6-bit → 3×8-bit

- `pmaddubsw [64,1,...]`: merge byte pairs → 12-bit words
- `pmaddwd [4096,1,...]`: merge word pairs → 24-bit dwords
- `pshufb`: byte-reverse within dwords, extract 12 output bytes

### Step 3: Store

- `movq` (8 bytes) + `psrldq` + `movd` (4 bytes) = 12 bytes output

Tail (remaining 4/8/12 bytes): same SSSE3 pipeline with `movd` load, 3-byte store per group.

## Kernel Interface

```c
int b64_decode_kern(const uint8_t *src, size_t src_len, uint8_t *dst);
```

`src_len` must be a multiple of 4. Assumes valid base64 input (no padding characters). Returns `src_len * 3 / 4`.

## Results

### Correctness

| Test | Result |
|------|--------|
| Sanity check ("Hello World!") | **PASS** — GCC and AI produce identical output |
| Differential fuzz (100K iterations) | **PASS** — 0 failures |
| Random data, lengths 3-300 (multiples of 3) | All outputs identical, roundtrip verified |

### Code Size

| Metric | GCC -O3 | AI (SSSE3) | Δ |
|--------|---------|------------|---|
| Instructions | 46 | 68 | +48% |
| Code bytes | 145 | 293 | +102% |

AI code is larger because it includes the SIMD pipeline (7 constants × 16 bytes = 112 bytes in .rodata, plus longer instruction sequences). This is expected — the optimization trades code size for throughput.

### Performance

| Input Size | GCC -O3 | AI (SSSE3) | Speedup | Verdict |
|------------|---------|------------|---------|---------|
| 64 bytes (50M iters) | 1.81s (1,767 MB/s) | 0.38s (8,479 MB/s) | **4.80x** | **AI_WINS** |
| 1024 bytes (5M iters) | 2.81s (1,825 MB/s) | 0.45s (11,365 MB/s) | **6.23x** | **AI_WINS** |
| 16384 bytes (200K iters) | 1.76s (1,857 MB/s) | 0.28s (11,635 MB/s) | **6.26x** | **AI_WINS** |

### Verdict

**AI WINS decisively on performance** — 4.8-6.3x faster across all input sizes. GCC's scalar code is limited to ~1.8 GB/s regardless of input size. The AI's SSSE3 version reaches 8.5-11.6 GB/s, with throughput increasing as input size grows (amortizing constant-loading overhead and reducing loop overhead relative to SIMD work).

## Analysis

### Why the AI wins by such a large margin

This is not a case of clever scheduling or register allocation. The AI wins because it uses a **fundamentally different algorithm** that GCC cannot discover:

1. **Table-free lookup:** The scalar version performs 4 random memory accesses (256-byte LUT) per 4 input bytes. Even if the LUT fits in L1 cache, each access has ~4 cycle latency and is data-dependent. The SSSE3 version replaces all 16 lookups per iteration with a single `pshufb` instruction (1 cycle, fully pipelined).

2. **16 bytes at once:** The scalar version processes 4 bytes per iteration. The SSSE3 version processes 16, achieving 4x parallelism before accounting for the lookup elimination.

3. **Pure register arithmetic:** After loading 16 input bytes, the SSSE3 pipeline is entirely register-to-register operations with no memory accesses until the store. The scalar version interleaves 4 memory loads (LUT lookups) with ALU operations, creating pipeline bubbles.

### Why GCC can't do this automatically

GCC's autovectorizer looks for patterns like "same operation on consecutive array elements" (map/reduce). Base64 decode doesn't fit because:
- The lookup table creates a **gather** pattern (data-dependent addresses)
- The 4:3 compression ratio means input and output don't have matching lane widths
- The `pshufb`-based nibble lookup is a creative algorithmic trick, not a mechanical transformation

This represents the strongest case for AI-generated assembly: kernels where SIMD requires **algorithmic insight** that a compiler's pattern matcher cannot discover.

## Files
- `b64_decode_kern.h` — Kernel interface
- `b64_decode_kern.c` — Scalar C reference (256-byte LUT, compiled by GCC)
- `b64_decode_kern_ai.S` — SSSE3 SIMD assembly (table-free vectorized lookup)
- `harness.c` — Differential fuzz + benchmark harness
- `build_and_test.sh` — Build and run script
