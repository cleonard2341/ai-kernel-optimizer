# AI-Optimized Assembly vs GCC -O3: Results on Three Production Kernels, Verified on 300K Inputs

GCC -O3 is good. On some workloads, it's *really* good. But there are classes of optimization it structurally cannot perform — and on those, AI-generated x86-64 assembly wins by 6x.

I tested this on three real-world computational kernels: base64 decoding, LZ4 decompression, and Redis's SipHash. Each was compiled with `gcc -O3 -march=native`, then challenged by hand-optimized assembly. Each was verified with 100,000 differential fuzz iterations — identical random inputs, byte-exact output comparison, zero tolerance for mismatches.

The results aren't "AI always wins." They're more interesting than that.

## The results

| Kernel | Domain | AI strategy | Speedup | Verdict |
|--------|--------|-------------|---------|---------|
| **Base64 decode** | Encoding | SSSE3 pshufb vectorization | **4.8–6.3x** | AI wins |
| **LZ4 fast decode** | Compression | SSE 16-byte match copy | **~1.05x** | AI wins (marginal) |
| **Redis SipHash** | Database | Reordered SIPROUND scheduling | **0.97x** | GCC wins |

300,000 fuzz iterations total. Zero failures.

## Base64 decode: 6.3x faster

Every web service decodes base64. JWT tokens, data URIs, binary payloads over JSON, email attachments. The standard implementation uses a 256-byte lookup table:

```c
dst[0] = (lut[src[0]] << 2) | (lut[src[1]] >> 4);
dst[1] = (lut[src[1]] << 4) | (lut[src[2]] >> 2);
dst[2] = (lut[src[2]] << 6) | lut[src[3]];
```

Four table lookups per group. Each one is a data-dependent memory access — the address depends on the input byte, so the CPU can't predict it. GCC compiles this to 46 instructions and ~1.8 GB/s. It's a tight loop. It's also the best GCC can do, because the 256-byte LUT creates a **gather pattern** that the autovectorizer cannot touch.

The AI version eliminates the table entirely.

The base64 alphabet has structure. All uppercase letters have ASCII high nibble 4 or 5. All lowercase have 6 or 7. Digits have 3. The `+` and `/` characters share nibble 2. That means a 16-byte lookup indexed by high nibble — one `pshufb` instruction — replaces all 16 table lookups per SIMD iteration.

The full pipeline: extract high nibbles (`psrlw` + `pand`), look up offsets (`pshufb`), correct for the `/` edge case (`pcmpeqb` + `pand`), apply offsets (`paddb`), then pack 6-bit values into bytes (`pmaddubsw` + `pmaddwd` + `pshufb`). Sixteen input bytes become twelve output bytes per iteration, entirely in registers, zero memory lookups after the initial load.

| Input size | GCC -O3 | AI (SSSE3) | Speedup |
|------------|---------|------------|---------|
| 64 bytes | 1,767 MB/s | 8,479 MB/s | 4.80x |
| 1,024 bytes | 1,825 MB/s | 11,365 MB/s | 6.23x |
| 16,384 bytes | 1,857 MB/s | 11,635 MB/s | 6.26x |

GCC's throughput is flat around 1.8 GB/s regardless of size — it's bottlenecked on table lookups. The AI version scales to 11.6 GB/s as loop overhead amortizes.

This isn't a case of the AI finding a slightly better instruction schedule. It's a fundamentally different algorithm. GCC cannot discover it because it requires understanding that the base64 alphabet's high-nibble structure enables a `pshufb` substitution. That's domain knowledge, not compiler optimization.

## LZ4 fast decode: modest win

LZ4's decompressor has a fast-path inner loop that handles the common case — literal length under 15, match length under 15, match offset at least 8. This loop processes 80–95% of all bytes in typical compressed data.

GCC compiles it to 64 instructions / 296 bytes. The AI version is 56 instructions / 153 bytes — 48% smaller. The key optimization: replacing GCC's two-step 8+8 byte match copy with a single SSE `vmovdqu` 16-byte load/store, and consolidating pointer arithmetic with a combined `lea` instruction.

Performance: approximately 1.02–1.07x in favor of the AI. Real but within noise on some runs. This is a case where GCC already produces good code — the AI's advantage is narrower because the optimization is incremental (wider memory operations), not algorithmic (different approach entirely).

## Redis SipHash: GCC wins

SipHash 1-2 is the hash function Redis calls on every key lookup. Every GET. Every SET. It's pure ALU — adds, rotates, XORs, with almost no memory access beyond loading the key.

GCC compiles it to 114 instructions / 570 bytes. The AI version tried to improve SIPROUND scheduling: reordering the second half to interleave independent dependency chains, deferring the `v3 ^= m` operation to exploit first-half independence, and interleaving pointer advances with SIPROUND operations.

Result: GCC is ~3% faster on short keys (8 bytes, Redis's most common workload). The AI version is 12% smaller in code size but loses on the metric that matters.

Why? GCC's finalization rounds use `lea` for 3-operand non-destructive addition and dynamically remap which registers hold which variables between rounds. This is a genuinely clever micro-optimization that's hard to replicate in hand-written assembly without making the code unmaintainable. On a kernel that's almost entirely register-to-register ALU operations, GCC's instruction scheduler is already near-optimal. There's nothing to exploit.

## The pattern

The three results form a clear pattern:

**The AI's advantage is proportional to the algorithmic distance between what GCC generates and what's possible.**

When the optimization requires the same algorithm with better scheduling (SipHash), GCC wins — its dependency analysis is mechanical and thorough. When it requires wider memory operations within the same algorithm (LZ4), the AI wins slightly. When it requires a completely different algorithm that the compiler structurally cannot discover (base64), the AI wins by 6x.

This makes sense. A compiler's autovectorizer pattern-matches loop bodies. It can vectorize `for (i=0; i<n; i++) dst[i] = src[i] + 1`. It cannot discover that a 256-byte lookup table can be replaced by a nibble-indexed `pshufb` — that requires understanding the mathematical structure of the data, which is outside the compiler's model of the world.

## Verification

Every number in this post is backed by differential fuzzing. The methodology:

1. Generate random input data (random binary for base64, random compressed blocks for LZ4, random keys and lengths for SipHash)
2. Run the GCC-compiled version and the AI assembly version on identical inputs
3. Compare outputs byte-by-byte (or hash-by-hash for SipHash)
4. Repeat 100,000 times per kernel

Any single mismatch fails the entire test. All three kernels pass with zero failures. The LZ4 harness uses four input generation strategies (pure random, repetitive, run-length, semi-random) to maximize coverage. The SipHash harness tests key lengths from 0 to 255 bytes. The base64 harness verifies roundtrip correctness: encode random data, decode with both implementations, compare to original.

The build scripts and verification reports are [on GitHub](https://github.com/cleonard2341/ai-kernel-optimizer). Run them yourself — each case study is a single `./build_and_test.sh` away from reproducing.

## What this means

This is not "AI replaces compilers." GCC handles the 99% — error paths, calling conventions, register allocation across complex control flow, correctness guarantees that would take years to replicate. The opportunity is the 1%: hot inner loops where SIMD requires algorithmic insight that pattern matchers can't provide.

The tooling (`optimize.py`) automates the boring parts — compiling the reference, generating fuzz harnesses, running benchmarks, declaring verdicts. The creative part — figuring out that base64's nibble structure enables a `pshufb` lookup — is where the value is.

Not every kernel will have a 6x win waiting. SipHash proves that. But the ones that do are often hiding in plain sight, in code that every server on the internet runs, compiled the same way it's been compiled for decades.

---

*Code, verification reports, and build scripts: [github.com/cleonard2341/ai-kernel-optimizer](https://github.com/cleonard2341/ai-kernel-optimizer)*
