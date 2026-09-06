"""Generate C++/C pseudo-source from an Analysis.

Recent dex2c builds are produced by the new lifting engine; bodies are real
reconstructions regardless of whether they fit in a .c or .cpp translation
unit. We emit ``.h`` + ``.cpp`` so callers can compile/lint the pseudo-code
directly: the JNIEnv uses stay plain C, while the recovered bodies may use
pseudo-C++ conveniences.
"""

from __future__ import annotations

import os
import re

from .reporting.report import (
    render_c_header, render_c_source_declarations, render_section_table,
    render_security,
)
from .decompile.arm64 import decompile_function


def generate_c(analysis, base, sha256_hex=None):
    """Write output/*.cpp / *.h files.  Returns list of (path, is_header)."""
    elf = analysis.elf
    out_dir = os.path.join(base, "decompiled")
    os.makedirs(out_dir, exist_ok=True)

    main_name = _sanitize_filename(elf.soname or "lib")
    header_name = f"{main_name}.h"
    source_name = f"{main_name}.cpp"

    header_lines, source_lines = _build_lines(analysis, sha256_hex)

    header_path = os.path.join(out_dir, header_name)
    source_path = os.path.join(out_dir, source_name)
    with open(header_path, "w") as f:
        f.write("\n".join(header_lines) + "\n")
    with open(source_path, "w") as f:
        f.write("\n".join(source_lines) + "\n")
    return [(header_path, True), (source_path, False)]


def _sanitize_filename(name):
    out = []
    for c in name:
        if c.isalnum() or c in "._-":
            out.append(c)
        else:
            out.append("_")
    s = "".join(out).strip("._")
    return s or "lib"


def _build_lines(analysis, sha256_hex):
    elf = analysis.elf
    arch = analysis.arch
    soname = elf.soname or "lib.so"

    # Recover every function boundary first (exports + internal helpers), so
    # bodies can name their companions (tail calls, local bl targets) and so
    # we can forward-declare the internal ones.
    functions = [f for f in analysis.functions if f.kind != "plt"]
    func_names = {f.addr: f.short_name for f in functions}

    # Decompile everything first so signatures can be recovered from the
    # GetMethodID() descriptor references inside each body.
    bodies = []
    str_idx = _build_str_index(analysis)
    resolver = analysis.resolver
    for j in analysis.jni_exports:
        lines = decompile_function(elf, resolver, str_idx, j.addr, j.size,
                                   j.name, func_names=func_names,
                                   entry_env=True)
        recovered_sig, recovered_name = _recover_from_body(lines)
        bodies.append({
            "export": j,
            "lines": lines,
            "sig": recovered_sig,        # e.g. "(Landroid/view/View;)I"
            "d2c_name": recovered_name,  # e.g. "lambda$0$..."
        })

    internal = []
    export_addrs = {b["export"].addr for b in bodies}
    for f in functions:
        if f.addr in export_addrs:
            continue
        addr, size = f.addr, f.size
        lines = decompile_function(elf, resolver, str_idx, addr, size,
                                   f.short_name, func_names=func_names,
                                   entry_env=False)
        internal.append({"f": f, "lines": lines})

    guard = ("SO2C_" + "".join(c.upper() if c.isalnum() else "_"
                               for c in soname) + "_H").replace("__", "_")

    header = []
    header += render_c_header(elf, None, arch.elf_name, soname, elf.build_id(),
                              sha256_hex)
    header.append(f"#ifndef {guard}")
    header.append(f"#define {guard}")
    header.append("")
    header.append("#include <jni.h>")
    header.append("#include <stdint.h>")
    header.append("#include <stddef.h>")
    header.append("")
    header.append("/* ---- Reconstructed JNI entry points ---- */")
    for body in bodies:
        j = body["export"]
        sig = body["sig"] if body["sig"] else _c_signature(j.signature)
        ret = _c_signature(sig) if body["sig"] else _c_signature(j.signature)
        header.append(f"JNIEXPORT {ret} JNICALL {j.name}")
        header.append(f"    (JNIEnv *env, jobject thiz{_extra_args(sig)});")
        header.append("")
    header.append("#endif")
    header.append("")

    source = []
    source += render_c_header(elf, None, arch.elf_name, soname, elf.build_id(),
                              sha256_hex)
    source.append("#include <jni.h>")
    source.append("#include <stdint.h>")
    source.append("#include <stddef.h>")
    if soname:
        source.append(f"#include \"{_sanitize_filename(soname)}.h\"")
    source.append("")
    source += render_c_source_declarations(elf, analysis.exports, analysis.imports)
    source.append("")
    source += render_import_decls(analysis)
    source.append("")
    source += _render_internal_decls(internal)
    source.append("")
    source += render_section_table(elf)
    source.append("")
    source += render_str_table(analysis)
    source.append("")
    source += render_imports(analysis)
    source.append("")
    source += render_security(analysis)
    source += [""]

    # ---- decompiled bodies: exported JNI methods ----
    source.append("/* ========================================================")
    source.append(" * Decompiled JNI entry points (pseudo-C reconstruction)")
    source.append(" * ========================================================")
    source.append("")

    for body in bodies:
        j = body["export"]
        sig = body["sig"]
        if not sig:
            sig = j.signature
        ret = _c_signature(sig) if sig else "void"
        source.append("/* -------------------------------------------------")
        source.append(f" * {j.name}  @ {j.addr:#x}")
        java_name = j.method
        if body["d2c_name"]:
            java_name = body["d2c_name"]
        source.append(f" *   java: {j.package}{j.class_name}.{java_name}"
                      f"{sig or ''}")
        source.append(f" *   abi : {arch.elf_name}")
        source.append(" * ------------------------------------------------- */")
        src = f"JNIEXPORT {ret} JNICALL {j.name}(JNIEnv *env, jobject thiz"
        src += _extra_args(sig)
        src += ") {"
        source.append(src)
        lines = body["lines"]
        if lines:
            source.extend(lines)
        else:
            source.append("    // <no disassembly available>")
        source.append("}")
        source.append("")

    # ---- decompiled bodies: internal / otherwise-unexported functions ----
    if internal:
        source.append("/* ========================================================")
        source.append(" * Internal functions recovered from .text (not exported)")
        source.append(" * --------------------------------------------------------")
        source.append(" * These have no ELF symbol, so their C signatures are")
        source.append(" * unknown; they are declared `static void` and each body")
        source.append(" * carries an honest note. They are emitted so every byte")
        source.append(" * of the executable region is accounted for.")
        source.append(" * ========================================================")
        source.append("")
        for it in internal:
            f = it["f"]
            source.append("/* -------------------------------------------------")
            source.append(f" * {f.short_name}  @ {f.addr:#x}  ({f.size} bytes)")
            source.append(f" *   reason : {f.kind}")
            source.append(f" *   sig    : unknown (recovered from stripped .text)")
            source.append(" * ------------------------------------------------- */")
            source.append(f"static void {f.short_name}(void) {{")
            source.append("    // signature unknown; do not hand-call with args")
            lines = it["lines"]
            if lines:
                source.extend(lines)
            else:
                source.append("    // <no disassembly available>")
            source.append("}")
            source.append("")
    return header, source


def render_import_decls(analysis):
    """Forward declarations for imports the generated bodies call, when the
    real signature is known (compiler-rt / bionic runtime glue)."""
    known = {
        "__stack_chk_fail":
            "extern \"C\" void __stack_chk_fail(void);",
        "__cxa_finalize":
            "extern \"C\" void __cxa_finalize(void *dso_handle);",
        "__cxa_atexit":
            "extern \"C\" int __cxa_atexit(void (*func)(void *), "
            "void *arg, void *dso_handle);",
    }
    out = ["/* ----- Runtime/compiler-rt imports referenced by bodies ----- */"]
    emitted = False
    for imp in analysis.imports:
        d = known.get(imp.name)
        if d:
            out.append(f"    {d}")
            emitted = True
    if not emitted:
        out.append("    // (none of the imports has a known-rendered signature)")
    out.append("")
    return out


def _render_internal_decls(internal):
    out = ["/* ----- Internal function forward declarations ----- */"]
    if not internal:
        out.append("    // (none)")
        out.append("")
        return out
    for it in internal:
        out.append(f"static void {it['f'].short_name}(void);")
    out.append("")
    return out


_SIG_RE = re.compile(r'"((?:d2c\$orig\$)[^"]+)"\s*,\s*"((\([^"\n]*\))[^"\n]*)"')
_NAME_RE = re.compile(r'"((?:d2c\$orig\$)[^"]+)"')


def _recover_from_body(lines):
    """Scan pseudo-C lines for a GetMethodID(..,"name","desc") call and return
    (desc, orig_name) if found."""
    sig = ""
    name = ""
    for line in lines:
        m = _SIG_RE.search(line)
        if m:
            cand_name, cand_sig = m.group(1), m.group(2)
            if cand_sig.startswith("("):
                sig = cand_sig
                name = cand_name
                continue
        m2 = _NAME_RE.search(line)
        if m2 and not name:
            name = m2.group(1)
    if name.startswith("d2c$orig$"):
        name = name[len("d2c$orig$"):]
    return sig, name


def _c_signature(jni_sig):
    """Map a JNI descriptor's return type to a C type."""
    if not jni_sig:
        return "void"
    import re
    m = re.match(r"\((.*)\)(.*)$", jni_sig)
    if not m:
        return "void"
    ret = m.group(2)
    return _ret_type(ret)


def _ret_type(desc):
    if desc == "V":
        return "void"
    if desc in ("Z",):
        return "jboolean"
    if desc == "B":
        return "jbyte"
    if desc == "C":
        return "jchar"
    if desc == "S":
        return "jshort"
    if desc == "I":
        return "jint"
    if desc == "J":
        return "jlong"
    if desc == "F":
        return "jfloat"
    if desc == "D":
        return "jdouble"
    if desc.startswith("L"):
        return "jobject"
    if desc == "[":
        return "jobject"
    if desc == "I":
        return "jint"
    return "jobject"


def _extra_args(jni_sig):
    """Return string like ", jint a" for the params part of the sig."""
    import re
    m = re.match(r"\((.*)\)", jni_sig or "")
    if not m:
        return ""
    params = m.group(1)
    return _param_types(params)


def _param_types(params):
    out = []
    i = 0
    name = ord("a")
    while i < len(params):
        c = params[i]
        depth = 0
        while i < len(params) and params[i] == "[":
            depth += 1
            i += 1
        if i >= len(params):
            break
        c = params[i]
        if c == "L":
            j = params.find(";", i)
            if j < 0:
                j = len(params) - 1
            typ = "jobject"
            i = j + 1
        else:
            typ = _ret_type(c)
            i += 1
        n = chr(name)
        name += 1
        out.append(f", {typ} {n}")
    return "".join(out)


def _build_str_index(analysis):
    idx = {}
    for h in analysis.strings:
        idx[h.addr] = h.content
    for h in analysis.decoded_strings:
        idx[h.addr] = h.content
    # Short JNI descriptor strings ("()I", "(I)F") fall under the main scan
    # minimum length but matter for signature recovery / rendering.
    import so2c.engine as eng
    try:
        idx.update(eng.str_index_for(analysis.elf, analysis))
    except Exception:
        pass
    return idx


def render_str_table(analysis):
    lines = ["/* ----- Referenced string constants ----- */"]
    for h in analysis.strings:
        lines.append(f"    // {h.addr:#010x} : \"{h.content}\"")
    for h in analysis.decoded_strings:
        lines.append(f"    // {h.addr:#010x} : [xor 0x{h.key:02x}] \"{h.content}\"")
    lines.append("")
    return lines


def render_imports(analysis):
    lines = ["/* ----- Imports (dynamic symbols pulled from dependencies) ----- */"]
    for imp in analysis.imports:
        lines.append(f"    // {imp.display}")
    return lines


def render_security(analysis):
    sec = analysis.security
    lines = ["/* ----- Security / hardening observations ----- */"]
    for k, v in sec.items():
        lines.append(f"    // {k:<24}: {v}")
    lines.append("")
    return lines