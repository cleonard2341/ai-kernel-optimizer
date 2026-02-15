# AI Kernel Optimization: Case Study Results

## Overview

Three production-code case studies testing whether AI-generated x86-64 assembly can beat GCC -O3 on real-world computational kernels. The results tell a nuanced story: the AI wins big when it can apply algorithmic insight (SIMD vectorization), wins marginally when it can exploit memory access patterns, and loses when GCC's scalar scheduler is already near-optimal.

| Case Study | Domain | Kernel | Fuzz | Code Size | Performance |
|------------|--------|--------|------|-----------|-------------|
| LZ4 fast decode | Compression | Inner fast-path loop | 100K PASS | **AI -48%** | **AI ~1.02-1.07x** |
| Redis SipHash | Database | SipHash 1-2 hash | 100K PASS | **AI -12%** | GCC ~1.03x (short keys) |
| Base64 decode | Encoding | LUT-based decode | 100K PASS | GCC smaller | **AI 4.8-6.3x** |

## The Three-Point Story

### AI wins decisively: SIMD vectorization (Base64 decode) — 4.8-6.3x
The scalar base64 decoder uses a 256-byte lookup table with 4 data-dependent memory accesses per group — a pattern GCC cannot auto-vectorize. The AI replaces the entire lookup with a SSSE3 `pshufb` nibble-based trick, processing 16 bytes per iteration with zero table lookups. This is an **algorithmic transformation** that requires creative insight, not just scheduling.

| Input Size | GCC -O3 | AI (SSSE3) | Speedup |
|------------|---------|------------|---------|
| 64 bytes | 1,767 MB/s | 8,479 MB/s | **4.80x** |
| 1024 bytes | 1,825 MB/s | 11,365 MB/s | **6.23x** |
| 16384 bytes | 1,857 MB/s | 11,635 MB/s | **6.26x** |

### AI wins marginally: Memory access patterns (LZ4 decode) — ~1.05x
The LZ4 fast decode kernel has clear memory access optimization opportunities. GCC's scalar 8+8 byte match copy is replaced by a single SSE `vmovdqu` 16-byte copy, and pointer arithmetic is consolidated with combined LEA instructions. These are pattern-level optimizations that GCC's instruction scheduler doesn't explore because they require semantic understanding of the data flow.

**Result:** 48% smaller code, marginal performance win.

### GCC wins: Pure ALU kernels (SipHash) — GCC ~1.03x
SipHash is almost entirely ALU operations (adds, rotates, XORs) with minimal memory access. GCC's instruction scheduler already produces near-optimal SIPROUND ordering with BMI2 rorx. More importantly, GCC's finalization uses LEA for 3-operand non-destructive addition and dynamically remaps register assignments between rounds — a micro-optimization that's hard to replicate in hand-written assembly without sacrificing code clarity.

**Result:** AI has smaller code, but GCC is 3-4% faster on Redis's typical short-key workload.

## Methodology

1. **Extract** a pure computational kernel from production code
2. **Compile** with GCC -O3 -march=native, analyze the output
3. **Write** AI-optimized x86-64 assembly targeting the same ABI
4. **Verify** with differential fuzzing (100K random inputs, byte-exact comparison)
5. **Benchmark** with realistic workloads

Both versions link against the same harness, use the same test data, and run back-to-back to minimize measurement bias.

### Correctness is non-negotiable
All three kernels pass 100K-iteration differential fuzz tests with zero failures (300K total fuzz iterations across all case studies). The LZ4 kernel required debugging a bounds-check bug in the harness. The SipHash kernel required a complete rewrite after incorrect register usage. Differential fuzzing caught issues that manual inspection missed.

## Honest Assessment

| Claim | Evidence |
|-------|----------|
| AI can produce correct assembly for real kernels | Yes — 300K total fuzz iterations, 0 failures |
| AI can beat GCC with algorithmic insight (SIMD) | **Yes — 4.8-6.3x on base64** |
| AI can beat GCC on memory-bound kernels | Yes — marginal win on LZ4 |
| AI can beat GCC on pure ALU kernels | No — GCC's scheduler is already near-optimal |
| AI can beat GCC on code size | Sometimes — 48% and 12% reductions on LZ4/SipHash, but larger on base64 |

## When Does AI-Generated Assembly Add Value?

The pattern is clear from three data points:

1. **Big wins** come from **algorithmic transformations** — using SIMD instructions that require creative insight to apply (pshufb lookup tricks, vectorized bit packing). GCC's autovectorizer cannot discover these because they require understanding the mathematical structure of the problem, not just pattern-matching loop bodies.

2. **Small wins** come from **memory access optimization** — replacing multiple narrow loads/stores with wider SIMD operations. GCC sometimes misses these because they span instruction boundaries that its optimizer doesn't cross.

3. **Losses** occur on **pure ALU kernels** where GCC's instruction scheduler is already near-optimal. On these workloads, the compiler's mechanical analysis of dependency chains and register pressure is hard to beat manually.

The takeaway: AI-generated assembly is most valuable when the optimization requires **domain knowledge** and **algorithmic creativity** — exactly the things compilers lack.
