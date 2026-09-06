"""SO2C command line entry point."""

from __future__ import annotations

import argparse
import json
import os
import sys

from .engine import (
    Analysis, load_elf, compute_sha256, str_index_for, write_summary,
)
from .generate_c import generate_c
from .reporting.report import ensure_dir


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="so2c",
        description="SO2C - Android .so analysis, deobfuscation & decompilation",
    )
    parser.add_argument("input", help="path to input ELF .so (default: input/lib.so)",
                        nargs="?", default="input/lib.so")
    parser.add_argument("-o", "--output", default="output",
                        help="output directory (default: output)")
    parser.add_argument("--json", action="store_true",
                        help="also dump full analysis JSON")
    parser.add_argument("--no-decompile", action="store_true",
                        help="skip C pseudo-source generation")
    parser.add_argument("--target-abis", nargs="*",
                        default=None,
                        help="report which ABIs are supported (informational)")
    args = parser.parse_args(argv)

    if not os.path.exists(args.input):
        print(f"[so2c] error: input file not found: {args.input}", file=sys.stderr)
        return 2

    input_path = args.input
    out_base = args.output
    ensure_dir(out_base)

    print(f"[so2c] analysing {input_path}")

    elf = load_elf(input_path)
    analysis = Analysis(elf)
    print(f"[so2c] architecture : {analysis.arch.elf_name} "
          f"({analysis.arch.abi}) {analysis.arch.word_size}-bit")
    print(f"[so2c] soname       : {elf.soname}")
    print(f"[so2c] stripped     : {analysis.is_stripped}")
    print(f"[so2c] exports      : {len(analysis.exports)}")
    print(f"[so2c] imports      : {len(analysis.imports)}")
    print(f"[so2c] strings      : {len(analysis.strings)}")
    print(f"[so2c] funcs        : {len(analysis.functions)} "
          f"({len([f for f in analysis.functions if f.kind != 'plt'])} in .text)")

    analysis.run_deobfuscation()
    if analysis.decoded_strings:
        print(f"[so2c] deobfuscated : {len(analysis.decoded_strings)} candidates")

    write_summary(analysis, out_base)
    print(f"[so2c] summary written to {os.path.join(out_base, 'summary')}")

    if not args.no_decompile:
        sha = compute_sha256(input_path)
        files = generate_c(analysis, out_base, sha)
        for path, is_header in files:
            print(f"[so2c] wrote {path}")

    print("[so2c] done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())