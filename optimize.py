#!/usr/bin/env python3
"""Kernel Optimizer — scan, analyze, verify, compete.

Usage:
  python3 optimize.py scan    <file.c> [file2.c ...]   # Find kernel candidates
  python3 optimize.py analyze <kernel.c>                # GCC output + AI prompt
  python3 optimize.py verify  <kernel.c> <kernel.S>     # Differential fuzz test
  python3 optimize.py compete <kernel.c> <kernel.S>     # Fuzz + benchmark + verdict
"""

import argparse, os, re, shutil, subprocess, sys, tempfile


# ── Function call classification ─────────────────────────────

# Calls that don't disqualify a function as a pure kernel
PURE_CALLS = {
    'memcpy', 'memset', 'memcmp', 'memmove',
    'ntohs', 'ntohl', 'htons', 'htonl',
    'abs', 'labs', 'llabs', 'fabs', 'fabsf',
    'sqrt', 'sqrtf', 'sin', 'sinf', 'cos', 'cosf',
    'tan', 'tanf', 'log', 'logf', 'exp', 'expf',
    'pow', 'powf', 'ceil', 'ceilf', 'floor', 'floorf',
    'round', 'roundf', 'fma', 'fmaf',
    '__builtin_expect', '__builtin_bswap16',
    '__builtin_bswap32', '__builtin_bswap64',
    '__builtin_ctz', '__builtin_clz', '__builtin_popcount',
}

IO_CALLS = {
    'printf', 'fprintf', 'sprintf', 'snprintf', 'puts', 'putchar',
    'fwrite', 'fread', 'fopen', 'fclose', 'fseek', 'ftell',
    'read', 'write', 'open', 'close', 'send', 'recv',
    'perror', 'strerror', 'syslog',
}

ALLOC_CALLS = {
    'malloc', 'calloc', 'realloc', 'free',
    'mmap', 'munmap', 'posix_memalign', 'aligned_alloc',
}

# Not-a-call patterns (types, keywords that appear before parens)
NOT_CALLS = {
    'if', 'while', 'for', 'switch', 'return', 'sizeof', 'do', 'else',
    'int', 'long', 'short', 'char', 'float', 'double', 'void',
    'unsigned', 'signed', 'struct', 'enum', 'union', 'const',
    'typeof', 'alignof', '_Alignof',
}


# ── Source parsing ───────────────────────────────────────────

def strip_comments(src):
    src = re.sub(r'/\*.*?\*/', ' ', src, flags=re.DOTALL)
    src = re.sub(r'//.*$', '', src, flags=re.MULTILINE)
    return src


def parse_kernel(c_path):
    """Extract first non-static function definition from C source."""
    src = strip_comments(open(c_path).read())
    clean = '\n'.join(l for l in src.split('\n') if not l.strip().startswith('#'))

    skip = {'if','while','for','switch','return','sizeof','do'}
    for m in re.finditer(r'([\w\s\*]+?)\s+(\w+)\s*\(([^)]*)\)\s*\{', clean):
        ret = m.group(1).strip()
        name = m.group(2)
        if 'extern' in ret or 'static' in ret or name in skip:
            continue
        params_str = m.group(3).strip()
        params = []
        if params_str and params_str != 'void':
            for raw in params_str.split(','):
                raw = raw.strip()
                is_const = 'const' in raw
                is_ptr = '*' in raw
                tokens = re.sub(r'\*', ' ', raw).split()
                pname = tokens[-1]
                tidx = raw.rfind(pname)
                ptype = raw[:tidx].strip()
                sm = re.search(r'struct\s+(\w+)', raw)
                params.append({
                    'decl': raw, 'name': pname, 'ptype': ptype,
                    'is_const': is_const, 'is_ptr': is_ptr,
                    'struct_name': sm.group(1) if sm else None,
                })
        return {'name': name, 'ret': ret, 'params': params,
                'params_str': params_str,
                'sig': f'{ret} {name}({params_str})'}
    return None


def parse_all_functions(c_path):
    """Extract all function definitions from a C file."""
    src = strip_comments(open(c_path).read())
    clean = '\n'.join(l for l in src.split('\n') if not l.strip().startswith('#'))

    skip = {'if','while','for','switch','return','sizeof','do'}
    functions = []

    for m in re.finditer(r'([\w\s\*]+?)\s+(\w+)\s*\(([^)]*)\)\s*\{', clean):
        ret = m.group(1).strip()
        name = m.group(2)
        if name in skip or 'extern' in ret:
            continue
        is_static = 'static' in ret
        params_str = m.group(3).strip()

        # Extract body by counting braces
        start = m.end() - 1
        depth, end = 0, start
        for i in range(start, len(clean)):
            if clean[i] == '{': depth += 1
            elif clean[i] == '}':
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        body = clean[start:end]

        functions.append({
            'name': name, 'ret': ret, 'params_str': params_str,
            'body': body, 'lines': body.count('\n'),
            'is_static': is_static,
        })

    return functions


def find_calls(body):
    """Find all function-call-like identifiers in a function body."""
    calls = set()
    for m in re.finditer(r'\b(\w+)\s*\(', body):
        name = m.group(1)
        if name not in NOT_CALLS:
            calls.add(name)
    return calls


# ── Kernel scoring ───────────────────────────────────────────

def score_kernel(func):
    """Score a function for kernel optimization potential.
    Returns (score, [signal_strings])."""
    body = func['body']
    signals = []
    score = 0.50

    calls = find_calls(body)

    # ── Negative signals ──

    if calls & IO_CALLS:
        score -= 0.30
        signals.append('I/O')

    if calls & ALLOC_CALLS:
        score -= 0.25
        signals.append('alloc')

    returns = len(re.findall(r'\breturn\b', body))
    if returns > 3:
        score -= min(0.20, 0.05 * (returns - 3))
        signals.append(f'{returns} returns')

    # Calls to functions that aren't known-safe library calls
    unknown = calls - PURE_CALLS - IO_CALLS - ALLOC_CALLS
    # Filter out type-like names (uint32_t, etc.)
    unknown = {c for c in unknown
               if not re.match(r'^u?int\d+_t$|^size_t$|^ssize_t$', c)}
    if unknown:
        score -= 0.08 * min(len(unknown), 3)
        top3 = sorted(unknown)[:3]
        signals.append(f'calls: {", ".join(top3)}')

    if re.search(r'\bgoto\b', body):
        score -= 0.10
        signals.append('goto')

    # ── Positive signals ──

    loops = len(re.findall(r'\b(for|while)\s*\(', body))
    if loops:
        score += 0.08 * min(loops, 3)
        signals.append(f'{loops} loop{"s" if loops > 1 else ""}')

    if 'memcpy' in calls:
        score += 0.10
        signals.append('memcpy')

    if calls & {'ntohs', 'ntohl', 'htons', 'htonl'}:
        score += 0.12
        signals.append('byte-swap')

    # Arithmetic density
    arith = len(re.findall(r'[+\-*/&|^~]', body))
    if func['lines'] > 0 and arith / max(func['lines'], 1) > 1.5:
        score += 0.08
        signals.append('arithmetic')

    # Size: too small or too large
    if func['lines'] < 3:
        score -= 0.25
        signals.append('tiny')
    elif func['lines'] > 80:
        score -= 0.08
        signals.append('large')

    return max(0.0, min(1.0, score)), signals


def compiled_stats(obj_path, func_name):
    """Get instruction-level stats for a compiled function."""
    out = subprocess.run(
        ['objdump', '-d', '--no-show-raw-insn', obj_path],
        capture_output=True, text=True).stdout

    in_fn, insns, branches, calls = False, 0, 0, 0
    for line in out.splitlines():
        if f'<{func_name}>:' in line:
            in_fn = True; continue
        if in_fn:
            m = re.match(r'\s+[0-9a-f]+:\s+(\S+)', line)
            if m:
                insns += 1
                mn = m.group(1)
                if mn.startswith('j') or mn.startswith('cmov'):
                    branches += 1
                if mn in ('call', 'callq'):
                    calls += 1
            elif line.strip() == '' or (line and not line[0].isspace()):
                break

    return {'insns': insns, 'branches': branches, 'calls': calls}


# ── Header/struct helpers ────────────────────────────────────

def find_header(c_path):
    base = os.path.dirname(os.path.abspath(c_path))
    for m in re.finditer(r'#include\s+"([^"]+)"', open(c_path).read()):
        p = os.path.join(base, m.group(1))
        if os.path.exists(p):
            return p
    return None


def get_struct_fields(header_path, struct_name):
    src = open(header_path).read()
    m = re.search(rf'struct\s+{struct_name}\s*\{{([^}}]+)\}}', src, re.DOTALL)
    if not m: return []
    fields = []
    for line in m.group(1).split('\n'):
        line = re.sub(r'/\*.*?\*/', '', line).strip()
        fm = re.search(r'(\w+)\s*(\[\w+\])?\s*;', line)
        if fm: fields.append(fm.group(1))
    return fields


def get_struct_layout(header_path, struct_name, fields, inc_dir, tmp):
    src = os.path.join(tmp, 'layout.c')
    with open(src, 'w') as f:
        f.write('#include <stddef.h>\n#include <stdio.h>\n')
        f.write(f'#include "{os.path.basename(header_path)}"\n')
        f.write('int main(){\n')
        f.write(f'  printf("sizeof(struct {struct_name}) = %zu\\n",'
                f'sizeof(struct {struct_name}));\n')
        for fld in fields:
            f.write(f'  printf("  %-20s  offset %3zu  size %zu\\n","{fld}",'
                    f'offsetof(struct {struct_name},{fld}),'
                    f'sizeof(((struct {struct_name}*)0)->{fld}));\n')
        f.write('}\n')
    b = os.path.join(tmp, 'layout')
    r = subprocess.run(['gcc','-I',inc_dir,'-o',b,src], capture_output=True, text=True)
    if r.returncode: return None
    return subprocess.run([b], capture_output=True, text=True).stdout


# ── Compilation helpers ──────────────────────────────────────

def count_insns(obj, sym=None):
    out = subprocess.run(['objdump','-d','--no-show-raw-insn',obj],
                         capture_output=True, text=True).stdout
    if not sym:
        return sum(1 for l in out.splitlines() if re.match(r'\s+[0-9a-f]+:', l))
    in_fn, n = False, 0
    for line in out.splitlines():
        if f'<{sym}>:' in line: in_fn = True; continue
        if in_fn:
            if re.match(r'\s+[0-9a-f]+:', line): n += 1
            elif line.strip() == '' or (line and not line[0].isspace()): break
    return n


def get_disasm(obj, sym=None):
    out = subprocess.run(['objdump','-d','--no-show-raw-insn','-M','intel',obj],
                         capture_output=True, text=True).stdout
    if not sym: return out
    lines, cap = [], False
    for l in out.splitlines():
        if f'<{sym}>:' in l: cap = True
        if cap:
            lines.append(l)
            if cap and l.strip() == '' and len(lines) > 1: break
    return '\n'.join(lines)


# ── Harness generation ──────────────────────────────────────

def gen_harness(ki, header, buf_size, fuzz_n, bench_n, scalar_max=256):
    fn = ki['name']
    ret = ki['ret']
    has_ret = ret.strip() != 'void'
    inputs  = [p for p in ki['params'] if p['is_ptr'] and (p['is_const'] or not p['struct_name'])]
    outputs = [p for p in ki['params'] if p['is_ptr'] and not p['is_const'] and p['struct_name']]
    scalars = [p for p in ki['params'] if not p['is_ptr']]
    out_st  = outputs[0]['struct_name'] if outputs else None

    C = []
    def w(s): C.append(s)

    w('#include <stdio.h>')
    w('#include <stdlib.h>')
    w('#include <stdint.h>')
    w('#include <string.h>')
    w('#include <time.h>')
    if header: w(f'#include "{os.path.basename(header)}"')
    w(f'\nextern {ret} gcc_{fn}({ki["params_str"]});')
    w(f'extern {ret} ai_{fn}({ki["params_str"]});\n')
    w('int main(void) {')
    w('    srand(42);')
    w('    int pass = 0, fail = 0;\n')

    def elem_type(p):
        return p['ptype'].replace('const','').replace('*','').strip() or 'uint8_t'

    # ── Fuzz ──
    w(f'    printf("-- Fuzz ({fuzz_n} iterations) --\\n");')
    w(f'    for (int i = 0; i < {fuzz_n}; i++) {{')
    for p in inputs:
        et = elem_type(p)
        w(f'        {et} __attribute__((aligned(32))) {p["name"]}[{buf_size}];')
        w(f'        for (int j = 0; j < {buf_size}; j++) {p["name"]}[j] = ({et})rand();')
    for p in scalars:
        stype = p['decl'][:p['decl'].rfind(p['name'])].strip()
        w(f'        {stype} {p["name"]} = ({stype})(rand() % {scalar_max});')
    if out_st:
        w(f'        struct {out_st} gcc_out, ai_out;')
        w(f'        memset(&gcc_out, 0, sizeof(gcc_out));')
        w(f'        memset(&ai_out, 0, sizeof(ai_out));')

    def call_args(ver):
        a = []
        for p in ki['params']:
            if p in inputs:   a.append(p['name'])
            elif p in outputs: a.append(f'&{ver}_out')
            else:              a.append(p['name'])
        return ', '.join(a)

    if has_ret:
        w(f'        {ret} gcc_rc = gcc_{fn}({call_args("gcc")});')
        w(f'        {ret} ai_rc  = ai_{fn}({call_args("ai")});')
    else:
        w(f'        gcc_{fn}({call_args("gcc")});')
        w(f'        ai_{fn}({call_args("ai")});')

    w('        int ok = 1;')
    if has_ret:
        w('        if (gcc_rc != ai_rc) {')
        w('            if (fail<5) printf("  #%d: return %lld vs %lld\\n",'
          ' i, (long long)gcc_rc, (long long)ai_rc);')
        w('            ok = 0;')
        w('        }')
    if out_st:
        w('        if (memcmp(&gcc_out, &ai_out, sizeof(gcc_out))) {')
        w('            if (fail<5) {')
        w('                printf("  #%d: struct mismatch\\n", i);')
        w('                unsigned char *g=(unsigned char*)&gcc_out,'
          ' *a=(unsigned char*)&ai_out;')
        w('                for (size_t b=0; b<sizeof(gcc_out); b++)')
        w('                    if (g[b]!=a[b]) printf("    byte %zu:'
          ' 0x%02x vs 0x%02x\\n", b, g[b], a[b]);')
        w('            }')
        w('            ok = 0;')
        w('        }')
    w('        if (ok) pass++; else fail++;')
    w('    }')
    w('    printf("Fuzz: %d/%d passed", pass, pass+fail);')
    w('    if (fail) printf(" (%d FAILURES)", fail);')
    w('    printf("\\n\\n");')
    w('    if (fail) { printf("VERDICT: FAIL\\n"); return 1; }\n')

    if bench_n <= 0:
        w('    printf("VERDICT: PASS\\n");')
        w('    return 0;')
        w('}')
        return '\n'.join(C) + '\n'

    # ── Benchmark ──
    w('    printf("-- Benchmark --\\n");')
    w('    struct timespec t0, t1;')
    w('    volatile int sink;')
    w('    int acc;\n')
    for p in inputs:
        et = elem_type(p)
        w(f'    {et} __attribute__((aligned(32))) b_{p["name"]}[{buf_size}];')
        w(f'    for (int j=0; j<{buf_size}; j++) b_{p["name"]}[j]=({et})(j*7+13);')
    for p in scalars:
        stype = p['decl'][:p['decl'].rfind(p['name'])].strip()
        w(f'    {stype} b_{p["name"]} = ({stype})42;')

    def bench_args(ver):
        a = []
        for p in ki['params']:
            if p in inputs:    a.append(f'b_{p["name"]}')
            elif p in outputs: a.append(f'&{ver}_bench')
            else:              a.append(f'b_{p["name"]}')
        return ', '.join(a)

    for ver in ['gcc', 'ai']:
        if out_st:
            w(f'    struct {out_st} {ver}_bench;')
            w(f'    memset(&{ver}_bench, 0, sizeof({ver}_bench));')
        w('    acc = 0;')
        w('    clock_gettime(CLOCK_MONOTONIC, &t0);')
        w(f'    for (long i = 0; i < {bench_n}L; i++) {{')
        if has_ret:
            w(f'        acc += (int){ver}_{fn}({bench_args(ver)});')
        else:
            w(f'        {ver}_{fn}({bench_args(ver)});')
            if out_st: w(f'        acc += ((int*)&{ver}_bench)[0];')
            else: w('        acc++;')
        w('    }')
        w('    clock_gettime(CLOCK_MONOTONIC, &t1);')
        w('    sink = acc;')
        w(f'    double {ver}_s = (t1.tv_sec-t0.tv_sec)+(t1.tv_nsec-t0.tv_nsec)/1e9;\n')

    w('    (void)sink;')
    w(f'    printf("  %ld iterations\\n", {bench_n}L);')
    w('    printf("  GCC -O3: %.4f s\\n", gcc_s);')
    w('    printf("  AI asm:  %.4f s\\n", ai_s);')
    w('    double ratio = gcc_s / ai_s;')
    w('    if (ratio > 1.02) printf("VERDICT: AI_WINS %.2fx\\n", ratio);')
    w('    else if (ratio < 0.98) printf("VERDICT: GCC_WINS %.2fx\\n", 1.0/ratio);')
    w('    else printf("VERDICT: TIE\\n");')
    w('    return 0;')
    w('}')
    return '\n'.join(C) + '\n'


# ── Commands ─────────────────────────────────────────────────

def cmd_scan(files, args):
    """Scan C files for kernel optimization candidates."""
    results = []

    for c_path in files:
        if not os.path.exists(c_path):
            print(f"Warning: {c_path} not found"); continue

        functions = parse_all_functions(c_path)
        if not functions: continue

        # Compile for instruction-level analysis
        compiled = {}
        with tempfile.TemporaryDirectory() as tmp:
            obj = os.path.join(tmp, 'scan.o')
            inc_dir = os.path.dirname(os.path.abspath(c_path))
            cflags = args.cflags.split() if args.cflags else []
            r = subprocess.run(
                ['gcc', '-O3', '-march=native'] + cflags +
                ['-I', inc_dir, '-c', c_path, '-o', obj],
                capture_output=True, text=True)
            if r.returncode == 0:
                for func in functions:
                    compiled[func['name']] = compiled_stats(obj, func['name'])

        for func in functions:
            score, signals = score_kernel(func)

            # Refine with compiled stats
            stats = compiled.get(func['name'], {})
            insns = stats.get('insns', 0)
            br = stats.get('branches', 0)

            if insns > 0:
                br_pct = br / insns
                if br_pct < 0.05:
                    score = min(1.0, score + 0.15)
                    signals.append('low-branch')
                elif br_pct > 0.20:
                    score = max(0.0, score - 0.10)
                    signals.append('high-branch')

                if stats.get('calls', 0) == 0:
                    score = min(1.0, score + 0.10)
                    signals.append('self-contained')

                if insns < 10:
                    score = max(0.0, score - 0.15)

            results.append({
                'name': func['name'],
                'file': os.path.basename(c_path),
                'path': c_path,
                'score': score,
                'signals': signals,
                'insns': insns,
                'branches': br,
                'lines': func['lines'],
            })

    if not results:
        print("No functions found."); return 1

    results.sort(key=lambda r: -r['score'])

    n_files = len(set(r['file'] for r in results))
    n_funcs = len(results)
    print(f"\nKERNEL SCAN — {n_files} file{'s' if n_files > 1 else ''},"
          f" {n_funcs} function{'s' if n_funcs > 1 else ''}")
    print("=" * 76)
    print(f" {'Score':>5}  {'Function':<24} {'File':<18} {'Insns':>5}"
          f"  {'Br%':>4}  Signals")
    print("-" * 76)

    THRESHOLD = 0.50
    drawn = False
    for r in results:
        if not drawn and r['score'] < THRESHOLD:
            print("~" * 76)
            drawn = True

        br_str = f"{r['branches']/r['insns']*100:.0f}%" if r['insns'] else "   -"
        in_str = f"{r['insns']:>5}" if r['insns'] else "    -"
        sig = ', '.join(r['signals'][:5])

        print(f" {r['score']:>5.2f}  {r['name']:<24} {r['file']:<18}"
              f" {in_str}  {br_str:>4}  {sig}")

    if not drawn:
        print("~" * 76)

    print("=" * 76)

    # Suggest next step
    top = [r for r in results if r['score'] >= THRESHOLD]
    if top:
        best = top[0]
        print(f"\n{len(top)} candidate{'s' if len(top) > 1 else ''}"
              f" above {THRESHOLD} threshold.")
        print(f"\nNext step:")
        print(f"  python3 optimize.py analyze {best['path']}")
    else:
        print(f"\nNo candidates above {THRESHOLD} threshold.")
        print("Functions below the line have structural code patterns")
        print("(error handling, I/O, allocation) that make kernel extraction risky.")

    return 0


def cmd_analyze(c_path, args):
    ki = parse_kernel(c_path)
    if not ki:
        print(f"No function found in {c_path}"); return 1
    header = find_header(c_path)
    inc_dir = os.path.dirname(os.path.abspath(c_path))

    with tempfile.TemporaryDirectory() as tmp:
        obj = os.path.join(tmp, 'kern.o')
        r = subprocess.run(
            ['gcc','-O3','-march=native','-c',c_path,'-o',obj],
            capture_output=True, text=True)
        if r.returncode:
            print(f"Compile error:\n{r.stderr}"); return 1

        n = count_insns(obj, ki['name'])
        da = get_disasm(obj, ki['name'])

        print("=" * 60)
        print(" KERNEL OPTIMIZER — analyze")
        print("=" * 60)
        print(f"\nTarget:  {ki['sig']}")
        print(f"Source:  {os.path.basename(c_path)}")
        if header:
            print(f"Header:  {os.path.basename(header)}")
        print(f"\nGCC -O3 -march=native: {n} instructions\n")
        print(da)

        for p in ki['params']:
            if p['is_ptr'] and not p['is_const'] and p['struct_name'] and header:
                fields = get_struct_fields(header, p['struct_name'])
                if fields:
                    layout = get_struct_layout(
                        header, p['struct_name'], fields, inc_dir, tmp)
                    if layout:
                        print(f"Struct layout:\n{layout}")

        abi_regs = ['rdi','rsi','rdx','rcx','r8','r9']
        abi = ', '.join(f'{abi_regs[i]} = {p["name"]}'
                        for i, p in enumerate(ki['params']) if i < 6)
        ai_name = os.path.splitext(os.path.basename(c_path))[0] + '_ai.S'

        print("-" * 60)
        print(" AI PROMPT")
        print("-" * 60)
        print(f"""
Write x86-64 assembly (.intel_syntax noprefix) implementing:

  {ki['sig']}

ABI: {abi}
Preserve: rbx, rbp, r12-r15
Available: SSE, AVX, AVX2, BMI, BMI2

Pure computational kernel — no error checking, inputs valid,
output struct pre-zeroed. Load, transform, store.

Save as:  {ai_name}
Verify:   python3 optimize.py compete {c_path} {ai_name}
""")
    return 0


def cmd_run(c_path, s_path, args, verify_only=False):
    ki = parse_kernel(c_path)
    if not ki:
        print(f"No function found in {c_path}"); return 1
    header = find_header(c_path)
    inc_dir = os.path.dirname(os.path.abspath(c_path))

    with tempfile.TemporaryDirectory() as tmp:
        gcc_o = os.path.join(tmp, 'gcc.o')
        ai_o  = os.path.join(tmp, 'ai.o')

        r = subprocess.run(
            ['gcc','-O3','-march=native','-c',c_path,'-o',gcc_o],
            capture_output=True, text=True)
        if r.returncode:
            print(f"GCC error:\n{r.stderr}"); return 1

        r = subprocess.run(['gcc','-c',s_path,'-o',ai_o],
                           capture_output=True, text=True)
        if r.returncode:
            print(f"AI asm error:\n{r.stderr}"); return 1

        gcc_n = count_insns(gcc_o, ki['name'])
        ai_n  = count_insns(ai_o, ki['name'])
        print(f"GCC kernel: {gcc_n} instructions")
        print(f"AI kernel:  {ai_n} instructions\n")

        subprocess.run(
            ['objcopy', f'--redefine-sym={ki["name"]}=gcc_{ki["name"]}', gcc_o],
            check=True, capture_output=True)
        subprocess.run(
            ['objcopy', f'--redefine-sym={ki["name"]}=ai_{ki["name"]}', ai_o],
            check=True, capture_output=True)

        bench_n = 0 if verify_only else args.bench_iters
        hsrc = gen_harness(ki, header, args.buf_size, args.fuzz_count, bench_n,
                           getattr(args, 'scalar_max', 256))
        hc = os.path.join(tmp, 'harness.c')
        with open(hc, 'w') as f: f.write(hsrc)

        hbin = os.path.join(tmp, 'harness')
        cmd = ['gcc', '-O2']
        if header: cmd += ['-I', inc_dir]
        cmd += ['-o', hbin, hc, gcc_o, ai_o]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode:
            print(f"Harness error:\n{r.stderr}")
            print(f"\nGenerated harness:\n{hsrc}")
            return 1

        r = subprocess.run([hbin], capture_output=True, text=True, timeout=300)
        print(r.stdout)
        if r.stderr: print(r.stderr)
        return r.returncode


def main():
    p = argparse.ArgumentParser(
        description='Kernel Optimizer — scan, analyze, verify, compete')
    sub = p.add_subparsers(dest='cmd')

    s = sub.add_parser('scan', help='Scan C files for kernel candidates')
    s.add_argument('files', nargs='+')
    s.add_argument('--cflags', default='', help='Extra compiler flags')

    a = sub.add_parser('analyze', help='Show GCC output + AI prompt')
    a.add_argument('kernel_c')

    for name in ['verify', 'compete']:
        s = sub.add_parser(name)
        s.add_argument('kernel_c')
        s.add_argument('kernel_s')
        s.add_argument('--buf-size', type=int, default=256)
        s.add_argument('--fuzz-count', type=int, default=100000)
        s.add_argument('--bench-iters', type=int, default=50000000)
        s.add_argument('--scalar-max', type=int, default=256,
                       help='Max value for random scalar inputs (default 256)')

    args = p.parse_args()
    if not args.cmd:
        p.print_help(); return

    if args.cmd == 'scan':
        sys.exit(cmd_scan(args.files, args))
    elif args.cmd == 'analyze':
        sys.exit(cmd_analyze(args.kernel_c, args))
    elif args.cmd == 'verify':
        sys.exit(cmd_run(args.kernel_c, args.kernel_s, args, verify_only=True))
    elif args.cmd == 'compete':
        sys.exit(cmd_run(args.kernel_c, args.kernel_s, args))


if __name__ == '__main__':
    main()
