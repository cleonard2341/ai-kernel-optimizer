# AI Kernel Optimizer

A system that extracts pure computational kernels from production C code and generates optimized x86-64 assembly that provably outperforms GCC -O3.

## How It Works

```
python3 optimize.py scan    <file.c>              # Find kernel candidates
python3 optimize.py analyze <kernel.c>            # GCC -O3 output + optimization prompt
python3 optimize.py verify  <kernel.c> <kernel.S> # 100K differential fuzz test
python3 optimize.py compete <kernel.c> <kernel.S> # Fuzz + benchmark + verdict
```

The tool identifies pure computational kernels (no I/O, no allocation, no global state), compiles them with GCC -O3, and provides the framework to verify and benchmark hand-optimized assembly replacements.

## Case Study Results

Three production-code kernels tested with 100K differential fuzz iterations each (300K total, zero failures):

| Kernel | Source | AI Strategy | Speedup | Verdict |
|--------|--------|-------------|---------|---------|
| Base64 decode | Standard LUT-based decoder | SSSE3 pshufb table-free vectorization | **4.8–6.3x** | **AI wins** |
| LZ4 fast decode | lz4 1.10.0 decompressor | SSE 16-byte match copy, combined LEA | ~1.05x | AI wins (marginal) |
| Redis SipHash | Redis 7.x hash function | Reordered SIPROUND, BMI2 rorx | 0.97x | GCC wins |

### The Pattern

The AI's advantage scales with **algorithmic distance** from what GCC can auto-generate:

- **Big wins** come from algorithmic transformations — replacing a 256-byte lookup table with a SSSE3 `pshufb` nibble trick is something GCC's autovectorizer structurally cannot discover
- **Small wins** come from memory access optimization — widening scalar copies to SIMD operations
- **Losses** occur on pure ALU kernels — GCC's instruction scheduler is already near-optimal on adds, rotates, and XORs

Full reports with methodology, GCC output analysis, and benchmark data:
- [`case_studies/SUMMARY.md`](case_studies/SUMMARY.md) — Three-point comparison
- [`case_studies/base64/REPORT.md`](case_studies/base64/REPORT.md) — 6.3x on base64 decode
- [`case_studies/lz4/REPORT.md`](case_studies/lz4/REPORT.md) — Marginal win on LZ4
- [`case_studies/redis/REPORT.md`](case_studies/redis/REPORT.md) — GCC wins on SipHash

## Requirements

- GCC with x86-64 support
- GNU binutils (objcopy, objdump)
- Python 3.6+
- Linux

## License

MIT
