# Case Study: LZ4 Fast Decode Kernel

## Target
**Library:** LZ4 1.10.0 (lz4/lz4)
**Function:** `LZ4_decompress_safe()` → inner fast decode loop (`LZ4_FAST_DEC_LOOP`)
**Domain:** Compression / decompression
**Why this kernel:** Called on every decompression operation. The fast decode loop handles the common case (literal length < 15, match length < 15, match offset >= 8) and processes the vast majority of bytes in typical workloads.

## Kernel Extraction

The full `LZ4_decompress_safe()` is 856 instructions — far too large for AI assembly. We extracted the **fast-path batch decoder**: the inner loop that processes common-case LZ4 sequences without falling back to the generic slow path.

**Signature:**
```c
int lz4_fast_decode(const uint8_t *src, uint8_t *dst,
                    const uint8_t *src_end, uint8_t *dst_end,
                    const uint8_t *dst_base, int *src_consumed);
```

**Kernel properties:** Pure function, no allocation, no I/O, no global state. Reads compressed input, writes decompressed output. Returns bytes written.

## GCC -O3 Output Analysis

GCC produces 64 instructions / 296 bytes. Key patterns:
- Scalar 8-byte loads/stores for literal copy (2x `mov` for 16 bytes)
- Scalar 8-byte loads for match copy (8+8+2 pattern for 18-byte overlap-safe copy)
- Clean token decode with shift+and
- Loop with bounds checking on both src and dst

## AI Optimizations

The AI version targets 3 specific improvements:

1. **SSE match copy** — `vmovdqu` 16-byte load/store replaces 2 scalar 8-byte loads + 2 stores for match copy. Saves 2 instructions per loop iteration.

2. **Combined pointer advancement** — `lea rbx, [rbp + rcx + 2]` merges the ip base advance and the +2 for the match offset field into a single LEA, saving 1 instruction per iteration.

3. **32-bit comparisons** — Uses `cmp eax, 15` instead of `cmp al, 15` to avoid operand-size prefix penalties on some microarchitectures.

## Results

### Correctness
| Test | Result |
|------|--------|
| Differential fuzz (100K iterations) | **PASS** — 0 failures |
| Random input lengths, random data | All outputs byte-identical |

### Code Size
| Metric | GCC -O3 | AI | Δ |
|--------|---------|-----|---|
| Instructions | 64 | 56 | **-12.5%** |
| Code bytes | 296 | 153 | **-48.3%** |

### Performance
| Run | GCC -O3 | AI | Ratio | Verdict |
|-----|---------|-----|-------|---------|
| Run 1 | 0.0259s | 0.0241s | 1.07x | AI_WINS |
| Run 2 | 0.0260s | 0.0266s | 0.98x | TIE |
| Run 3 | 0.0245s | 0.0240s | 1.02x | AI_WINS |

**Benchmark config:** 10M iterations, 4096-byte blocks compressed to ~2229 bytes (~1.8:1 ratio).

### Verdict
**AI WINS on code size** (48% smaller). **TIE to slight AI win on performance** (~1.02-1.07x, within measurement noise). The SSE match copy optimization gives a real but small advantage; the main loop is tight enough that both versions are near-optimal.

## Files
- `lz4_fast_kern.h` — Kernel interface
- `lz4_fast_kern.c` — C reference (GCC compiles this)
- `lz4_fast_kern_ai.S` — AI-optimized x86-64 assembly
- `harness.c` — Differential fuzz + benchmark harness
- `build_and_test.sh` — Build and run script
