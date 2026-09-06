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
* readable C/C++ pseudo-source in `output/`

It is built to handle **stripped** libraries: when `.symtab` is absent we
still recover every exported dynamic symbol, JNI name demangling, and (with
capstone) a full disassembly of each exported function.

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
#    output/summary/strings.txt    - extracted string constants
#    output/summary/exports.txt    - recovered exported symbols
#    output/decompiled/*.c/.h      - reconstructed C pseudo-source
```

## GitHub Actions

The repository ships `.github/workflows/decompile.yml`, triggered manually via
`workflow_dispatch`.  It:

1. checks out the repository (with `input/lib.so`)
2. installs Python + `capstone`
3. runs the SO2C pipeline against `input/lib.so`
4. uploads all generated output (summary JSON/text and decompiled C/C++)
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
```

## Notes on fidelity

We are *deliberately conservative*: the decompiled C is a faithful,
readable reconstruction (a debugger-style linear listing with resolved string,
import, and JNI references) rather than a full register-tracking decompiler.
Everything the tool prints is derived from ELF metadata or real instruction
decoding, never guessed past what the binary proves.

## License

MIT.  Provided for interoperability, education and debugging of libraries you
have permission to analyse.
