# SO2C

**Android shared-object analysis, deobfuscation and decompilation.**

SO2C is a production-oriented Python toolkit that ingests an Android `.so`
shared library (or any ELF) and produces:

* ELF architecture / ABI auto-detection (`arm64-v8a`, `armeabi-v7a`,
  `x86`, `x86_64`), including endianness and word size
* a full analysis summary: sections, segments, imports/exports,
  JNI exports, string constants, security/hardening metadata
* string constant extraction **and** best-effort deobfuscation
  (single-byte XOR candidates against `.rodata`)
* JNI-aware decompilation: JNIEnv vtable calls are resolved to their
  JNI method names, string literals and relocation targets are recovered
* function-boundary recovery: exported **and** internal (non-symbolic)
  functions are discovered from `.text`, with gap-free, 4-byte aligned
  coverage of the whole executable range
* readable C/C++ pseudo-source in `output/`

It is built to handle **stripped** libraries: when `.symtab` is absent we
still recover every exported dynamic symbol, JNI name demangling, and (with
capstone) a full disassembly of each exported function.  Function discovery
uses a hybrid recursive-descent + anchor algorithm so every function in the
executable region — not just the exported ones — is accounted for, even when
no symbol table is present.

## Function discovery

For stripped binaries the exports alone only cover part of `.text`.  SO2C
recovers **all** functions by combining two strategies:

* **Recursive descent** from known entry points (exports and PLT resolvers):
  follow conditional branches, tail `b` jumps and `bl`/`blr` targets.
* **Anchor scanning**: fixpoint over unreached runs, treating any run whose
  preceding instruction is a control-flow terminator (`ret`/`br`/`b`) as a
  new function start.

The result is a gap-free, non-overlapping partition of every executable
region, so internal helpers, trampolines and cold blocks that a stripped
ELF would otherwise hide show up in the decompiled output (`static void
sub_XXXX` bodies in the `.cpp`).

## Architecture support

| ELF machine  | Android ABI     | Word | Decompiler |
|--------------|-----------------|------|------------|
| AArch64      | `arm64-v8a`     | 64   | full       |
| ARM          | `armeabi-v7a`   | 32   | listing    |
| x86_64       | `x86_64`        | 64   | listing    |
| x86          | `x86`           | 32   | listing    |

The ELF reader itself is dependency-free and supports all four ABIs, both
endiannesses and both word sizes.  Optional `capstone` enables disassembly;
without it the pipeline still runs and produces raw-byte dumps.

## Quick start

```bash
# 1. put the target library in place
cp yourlib.so input/lib.so

# 2. run locally (capstone optional but recommended)
pip install capstone
python -m so2c input/lib.so -o output

# 3. outputs
#    output/summary/analysis.json  - full machine-readable analysis
#    output/summary/functions.txt  - recovered function table (exports + internal)
#    output/summary/strings.txt    - extracted string constants
#    output/summary/exports.txt    - recovered exported symbols
#    output/decompiled/*.cpp/.h    - reconstructed C++ pseudo-source
```

## GitHub Actions

The repository ships `.github/workflows/decompile.yml`, triggered manually via
`workflow_dispatch`.  It:

1. checks out the repository (with `input/lib.so`)
2. installs Python + `capstone`
3. runs the SO2C pipeline against `input/lib.so`
4. uploads all generated output (summary JSON/text and decompiled pseudo-C++)
   as a downloadable **GitHub Actions artifact**

To run it: open the Actions tab -> *Decompile .so* -> **Run workflow**.

## Project layout

```
.github/workflows/decompile.yml   CI pipeline
input/                            drop your .so here
output/                           generated analysis + pseudo-C
src/so2c/
  elf/        dependency-free ELF reader + arch/symbols/strings analysis
  disasm/     capstone wrapper
  jni/        JNI export & registration-table analysis
  decompile/  AArch64 lifting / pseudo-C generation
  reporting/  text renderers
  cli.py      command line entry point
  engine.py   analysis orchestration
  generate_c.py
tests/        regression suite (pytest; needs input/lib.so)
```

## Development

```bash
pip install -e '.[dev]'
python -m pytest tests
```

The test suite (`tests/`) covers function-boundary recovery, the AArch64
lifter unit paths (store/load disambiguation, condition mapping, constant and
address rendering), end-to-end JNI decompilation with stack-canary recovery,
and the generated `.cpp`/`.h` structure.  Tests requiring the sample
`input/lib.so` are skipped automatically when it is absent.

## Notes on fidelity

We are *deliberately conservative*: the decompiled C++ is a faithful,
readable reconstruction using AArch64 register tracking — it recovers JNI
vtable lookups, argument-passing patterns, stack canary checks, and method
descriptor strings to emit real `jclass`/`jmethodID`/`jvalue` expressions.
Where the lifter cannot determine meaning it emits a comment with the raw
instruction, never a guess beyond what the binary proves.

## License

MIT.  Provided for interoperability, education and debugging of libraries you
have permission to analyse.
