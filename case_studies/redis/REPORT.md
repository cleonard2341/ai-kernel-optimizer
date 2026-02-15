# Case Study: Redis SipHash Kernel

## Target
**Library:** Redis 7.x (redis/redis)
**Function:** `siphash()` in `src/siphash.c` — SipHash 1-2 variant
**Domain:** Database / hash table
**Why this kernel:** Called on every key lookup — every GET, SET, and virtually every Redis command. Pure computational kernel: bytes + 16-byte key → 64-bit hash. No I/O, no allocation, no global state.

## Kernel Extraction

SipHash 1-2 is already a clean, self-contained function. Extracted directly with no modification to the algorithm.

**Signature:**
```c
uint64_t siphash_kern(const uint8_t *in, size_t inlen, const uint8_t *k);
```

**Algorithm:** 1 compression round (SIPROUND) per 8-byte input block, 2 finalization rounds. Each SIPROUND is 4 adds + 5 rotates + 4 XORs = 13 ALU operations.

## GCC -O3 Output Analysis

GCC produces 114 instructions / 570 bytes. Key patterns:
- **BMI2 `rorx`** for non-destructive rotates (1 cycle latency, no flags clobber)
- **Jump table** for 0-7 tail byte switch (movsxd + add + notrack jmp)
- **Instruction reordering** for ILP: first-half SIPROUND (v0,v1 chain) interleaved with second-half (v2,v3 chain)
- **LEA-based finalization** — GCC uses `lea rdi,[rcx+rax*1]` for combined addition and register remapping during finalization rounds, saving instructions

## AI Optimizations

The AI version matches GCC's approach (same register allocation, same jump table) and attempts to improve SIPROUND scheduling:

1. **Main loop interleaving** — Reorders the second half of SIPROUND to interleave chains A (v0,v3 operations) and B (v2,v1 operations) for better OoO execution: sequence 11,12,8,13,9,14,10 instead of 8,9,10,11,12,13,14.

2. **v3^=m placement** — Defers `v3 ^= m` from before SIPROUND to between the first-half and second-half, exploiting the fact that the first half (steps 1-4) doesn't touch v2/v3.

3. **Pointer advance interleaving** — Places `add rdi, 8` between independent operations in the main loop.

## Results

### Correctness
| Test | Result |
|------|--------|
| Sanity check (known input) | **PASS** — GCC and AI produce identical hash |
| Differential fuzz (100K iterations) | **PASS** — 0 failures |
| Random keys, random lengths 0-255 | All hashes identical |

### Code Size
| Metric | GCC -O3 | AI | Δ |
|--------|---------|-----|---|
| Code bytes | 570 | 503 | **-11.8%** |

AI is smaller despite having more individual instructions. GCC's endbr64, nop padding, and longer VEX-encoded sequences inflate its code size.

### Performance
| Key Size | GCC -O3 | AI | Ratio | Verdict |
|----------|---------|-----|-------|---------|
| 8 bytes (200M iters) | 1.379s | 1.438s | 0.96x | **GCC_WINS** |
| 32 bytes (100M iters) | 1.186s | 1.219s | 0.97x | **GCC_WINS** |
| 128 bytes (50M iters) | 1.632s | 1.647s | 0.99x | TIE |

### Verdict
**GCC WINS on performance** for short keys (~3-4% faster), which is Redis's primary workload. **AI wins on code size** (12% smaller). **TIE on long keys** where the main loop dominates.

**Why GCC wins:** GCC's finalization is genuinely clever. It uses `lea` for 3-operand non-destructive addition and dynamically remaps which registers hold which variables between finalization rounds, eliminating register-register moves. The AI version uses the same SIPROUND template for all 3 finalization rounds, which is cleaner but less optimal. For short keys (8 bytes = 1 block), finalization dominates runtime, so GCC's advantage there is amplified.

## Analysis

This result demonstrates that GCC -O3 is a strong competitor on pure ALU-bound kernels with no memory access patterns to exploit. SipHash is almost entirely ALU operations (adds, rotates, XORs) with minimal memory access — exactly the workload where GCC's instruction scheduler excels. The AI's opportunities are limited to:
- Instruction scheduling (both versions are similarly good)
- Register allocation (GCC's finalization remapping is hard to replicate manually)

The AI would need to pursue fundamentally different strategies (e.g., 128-bit SIMD SipHash, or batched multi-key hashing) to achieve meaningful speedups — but those would change the kernel interface, not just optimize within it.

## Files
- `siphash_kern.h` — Kernel interface
- `siphash_kern.c` — C reference (GCC compiles this)
- `siphash_kern_ai.S` — AI-optimized x86-64 assembly
- `harness.c` — Differential fuzz + benchmark harness
- `build_and_test.sh` — Build and run script
