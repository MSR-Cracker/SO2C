"""SO2C engine: coordinates all analysis and output generation."""

from __future__ import annotations

import hashlib
import json
import os

from .elf.reader import ELFReader
from .elf.arch import detect_arch, cs_config
from .elf.symbols import (
    ImportResolver, collect_exports, collect_imports, analyse_security,
    find_executable_sections,
)
from .elf.strings import scan_alloc_strings, Deobfuscator
from .jni.analyzer import (
    detect_jni_exports, detect_jni_registration_tables, parse_d2c_signature,
    JNI_FUNCS,
)
from .reporting.report import (
    ensure_dir, render_c_header, render_c_source_declarations,
    render_startup, render_section_table, render_string_header,
    render_security,
)


class Analysis:
    """Container of every analysis result for one ELF."""

    def __init__(self, elf: ELFReader):
        self.elf = elf
        self.arch = detect_arch(elf)
        self.resolver = ImportResolver(elf)
        self.exports = collect_exports(elf)
        self.imports = collect_imports(elf, self.resolver)
        self.security = analyse_security(elf)
        self.sections = list(elf.sections)
        self.exec_ranges = find_executable_sections(elf)
        self.strings = scan_alloc_strings(elf)
        self.decoded_strings = []
        self.jni_exports = detect_jni_exports(elf)
        self.registered = detect_jni_registration_tables(elf)
        self.has_symtab = bool(elf.symtab and any(s.name for s in elf.symtab))
        self.is_stripped = self._estimate_stripped(elf)
        self.notes = [{"name": n.name, "type": n.type, "desc": n.desc} for n in elf.notes]

    @staticmethod
    def _estimate_stripped(elf: ELFReader):
        symtab = elf.section_by_name(".symtab")
        if symtab is None or symtab.size == 0:
            return True
        return not any(s.name and not s.name.startswith(".") and s.is_defined
                       for s in elf.symtab if s.type in (1, 2))

    def run_deobfuscation(self):
        dec = Deobfuscator(self.elf)
        self.decoded_strings = dec.run()
        return self.decoded_strings

    @property
    def functions(self):
        """Recovered function list (exported + internal + .plt stubs).

        Computed lazily and cached; see so2c.decompile.functscan for the
        boundary-recovery algorithm used on stripped binaries.
        """
        if getattr(self, "_functions", None) is None:
            from .decompile.functscan import discover_functions
            self._functions = discover_functions(self.elf, self.resolver)
        return self._functions


def load_elf(path: str) -> ELFReader:
    with open(path, "rb") as f:
        data = f.read()
    return ELFReader(data)


def compute_sha256(path: str):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def str_index_for(elf: ELFReader, analysis):
    idx = {}
    for hit in analysis.strings:
        idx[hit.addr] = hit.content
    for hit in analysis.decoded_strings:
        idx[hit.addr] = hit.content
    # Short JNI descriptor strings ("()I", "(I)F") matter for decompilation
    # but fall below the main scan minimum length.
    from .elf.strings import scan_alloc_strings
    try:
        for hit in scan_alloc_strings(elf, min_len=3):
            if len(hit.content) == 3 and hit.content.startswith("("):
                idx.setdefault(hit.addr, hit.content)
    except Exception:
        pass
    return idx


def output_summary_dir(base):
    return ensure_dir(os.path.join(base, "summary"))


def json_default(o):
    if hasattr(o, "__dict__"):
        return o.__dict__
    if isinstance(o, bytes):
        return o.decode("utf-8", "replace")
    return str(o)


def write_summary(analysis, base):
    summary_dir = output_summary_dir(base)
    elf = analysis.elf

    arch_info = {
        "elf_machine": elf.machine,
        "arch": analysis.arch.elf_name,
        "abi": analysis.arch.abi,
        "class": "ELF32" if not elf.is64 else "ELF64",
        "endian": elf.byteorder,
        "entry": elf.entry,
        "pie": elf.pie,
        "e_flags": elf.e_flags,
    }

    meta = {
        "elf": arch_info,
        "soname": elf.soname,
        "needed": elf.needed,
        "build_id": elf.build_id(),
        "android_min_api": elf.android_api,
        "stripped": analysis.is_stripped,
        "has_symtab": analysis.has_symtab,
        "capstone": True,
    }

    sections = [
        {
            "idx": s.index, "name": s.name, "type": s.type,
            "addr": s.addr, "size": s.size, "flags": s.flags,
        }
        for s in elf.sections
    ]

    exports = []
    for e in analysis.exports:
        d = e.__dict__.copy()
        exports.append(d)

    imports = [{"name": i.name, "version": i.version, "via": i.via,
                "plt_addr": i.plt_addr} for i in analysis.imports]

    imports_formatted = [i.display for i in analysis.imports]

    strings = [
        {"addr": h.addr, "value": h.content, "section": h.section, "len": h.length}
        for h in analysis.strings
    ]

    decoded = [
        {"addr": h.addr, "value": h.content, "key": h.key} for h in analysis.decoded_strings
    ]

    jni_exports_out = []
    for j in analysis.jni_exports:
        jni_exports_out.append({
            "name": j.name,
            "address": j.addr,
            "size": j.size,
            "java_class": (j.package + j.class_name) if j.package else j.class_name,
            "java_method": j.method,
            "signature": j.signature,
        })

    registered_out = [{
        "java_class": r.java_class,
        "java_name": r.java_name,
        "signature": r.signature,
        "func_addr": r.func_addr,
        "func_name": r.func_name,
    } for r in analysis.registered]

    security = {
        "bind_now": analysis.security.get("bind_now"),
        "soname": analysis.security.get("soname"),
        "needed": analysis.security.get("needed"),
        "has_stack_protector": analysis.security.get("has_stack_protector"),
        "has_fortify": analysis.security.get("has_fortify"),
        "android_min_api": analysis.security.get("android_min_api"),
        "build_id": analysis.security.get("build_id"),
        "pie": analysis.security.get("pie"),
    }

    functions = []
    for f in analysis.functions:
        functions.append({
            "address": f.addr,
            "size": f.size,
            "kind": f.kind,
            "name": f.short_name,
            "section": f.section,
        })

    result = {
        "meta": meta,
        "sections": sections,
        "exports": exports,
        "imports": imports,
        "strings": strings,
        "decoded_strings": decoded,
        "jni_exports": jni_exports_out,
        "registered_natives": registered_out,
        "security": security,
        "exec_ranges": analysis.exec_ranges,
        "functions": functions,
    }

    with open(os.path.join(summary_dir, "analysis.json"), "w") as f:
        json.dump(result, f, indent=2, default=json_default)

    write_strings_txt(analysis, summary_dir)
    write_exports_txt(analysis, summary_dir)
    write_functions_txt(analysis, summary_dir)
    return result


def write_strings_txt(analysis, summary_dir):
    path = os.path.join(summary_dir, "strings.txt")
    with open(path, "w") as f:
        f.write("# SO2C extracted string constants\n")
        f.write("# addr      section       value\n")
        for h in analysis.strings:
            f.write(f"{h.addr:#010x} {h.section:<16} \"{h.content}\"\n")
        for h in analysis.decoded_strings:
            f.write(f"{h.addr:#010x} {h.section:<16} [xor 0x{h.key:02x}] \"{h.content}\"\n")
    return path


def write_exports_txt(analysis, summary_dir):
    path = os.path.join(summary_dir, "exports.txt")
    with open(path, "w") as f:
        f.write("# SO2C exports (defined dynamic symbols)\n")
        f.write(f"{'address':>12} {'size':>8} {'type':<7} {'bind':<7}  name\n")
        for e in analysis.exports:
            f.write(f"{e.addr:#010x} {e.size:>8} {e.type:<7} {e.bind:<7}  {e.name}\n")
    return path


def write_functions_txt(analysis, summary_dir):
    path = os.path.join(summary_dir, "functions.txt")
    with open(path, "w") as f:
        f.write("# SO2C recovered functions (exports + internal + .plt stubs)\n")
        f.write("#       address  size     kind  section  name\n")
        for fn in analysis.functions:
            f.write(f"{fn.addr:#010x} {fn.size:>6}  {fn.kind:<9} {fn.section:<7}  {fn.short_name}\n")
    return path