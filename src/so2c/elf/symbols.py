"""High level ELF analysis: imports/exports, dynamic linkage, security flags."""

from __future__ import annotations

from dataclasses import dataclass, field

from .reader import (
    ELFReader, ELFSymbol, STB_GLOBAL, STB_WEAK, STT_FUNC, STT_OBJECT,
    SHN_UNDEF, DT_FLAGS, DT_SONAME, DT_NEEDED,
)


@dataclass
class ImportEntry:
    name: str
    version: str = ""
    plt_addr: int = 0
    plt_slot: int = 0
    got_addr: int = 0
    via: str = ""

    @property
    def display(self):
        if self.version:
            return f"{self.name}@{self.version}"
        return self.name


@dataclass
class ExportEntry:
    name: str
    addr: int
    size: int
    bind: str
    type: str
    section: str = ""
    jni: bool = False
    jni_method: str = ""

    @property
    def jni_short(self):
        if not self.jni:
            return ""
        return self.jni_method


class ImportResolver:
    """Maps addresses to imported symbol names.

    Two kinds of address get resolved:

      * addresses inside .plt (the lazy-binding trampolines) -> import name
      * GOT slots filled by .rela.plt -> import name
      * addresses of relocated data pointers in .rela.dyn / .rel.dyn
    """

    def __init__(self, elf: ELFReader):
        self.elf = elf
        self.plt_ranges: dict[int, str] = {}     # (addr, addr+size) -> name
        self.got_slots: dict[int, str] = {}      # GOT addr -> name
        self.reloc_targets: dict[int, str] = {}  # reloc site -> name
        self.any_plt_addr: tuple = (0, 0)
        self._build()

    def _build(self):
        elf = self.elf
        syms = {s.index: s for s in elf.dynsym}
        jmprel = elf.jmprel

        plt = elf.section_by_name(".plt")
        if plt is not None and jmprel:
            # PLT header sizes: aarch64/arm 0x20, x86_64/x86 0x10.
            self.any_plt_addr = (plt.addr, plt.addr + plt.size)
            if elf.arch_name in ("aarch64", "arm"):
                header = 0x20
                entry_size = 16 if elf.arch_name == "aarch64" else 12
            else:
                header = 0x10
                entry_size = 16
            idx = 0
            seen_offsets = {}
            for r in jmprel:
                # map got addr
                s = syms.get(r.sym_index)
                if s and s.name:
                    by_type = None
                    if elf.arch_name in ("aarch64",):
                        if r.type in (1026, 1028):  # JUMP_SLOT / GLOB_DAT
                            by_type = s.name
                    elif elf.arch_name in ("arm",):
                        if r.type in (22, 21):
                            by_type = s.name
                    elif elf.arch_name in ("x86_64", "x86"):
                        if r.type in (7, 6):
                            by_type = s.name
                    if by_type is None:
                        by_type = s.name
                    if r.offset in seen_offsets:
                        continue
                    seen_offsets[r.offset] = s.name
                    self.got_slots[r.offset] = by_type
            # PLT entry k corresponds to jmprel[k] (standard layout).
            slot = header
            for r in jmprel:
                s = syms.get(r.sym_index)
                name = s.name if s else None
                if name:
                    self.plt_ranges[plt.addr + slot] = name
                slot += entry_size

        for r in elf.relocs:
            s = syms.get(r.sym_index)
            if s and s.name:
                self.reloc_targets[r.offset] = s.name

    def plt_name(self, addr):
        if addr in self.plt_ranges:
            return self.plt_ranges[addr]
        return None

    def got_name(self, addr):
        return self.got_slots.get(addr)

    def reloc_name(self, addr):
        return self.reloc_targets.get(addr)

    def resolve(self, addr):
        name = self.plt_name(addr)
        if name:
            return name
        name = self.got_name(addr)
        if name:
            return name
        name = self.reloc_name(addr)
        if name:
            return name
        return None

    def inside_plt(self, addr):
        if not self.any_plt_addr or self.any_plt_addr == (0, 0):
            return False
        lo, hi = self.any_plt_addr
        return lo <= addr < hi


def _bind_name(b):
    return {0: "LOCAL", 1: "GLOBAL", 2: "WEAK"}.get(b, f"other({b})")


def _type_name(t):
    names = {0: "NOTYPE", 1: "OBJECT", 2: "FUNC", 3: "SECTION", 4: "FILE"}
    return names.get(t, f"type({t})")


def _sec_name(elf, shndx):
    if shndx == SHN_UNDEF:
        return "UND"
    for s in elf.sections:
        if s.index == shndx:
            return s.name
    return f"shndx({shndx})"


def collect_exports(elf: ELFReader):
    out = []
    for sym in elf.dynsym:
        if not sym.is_defined:
            continue
        if not sym.name:
            continue
        e = ExportEntry(
            name=sym.name,
            addr=sym.value,
            size=sym.size,
            bind=_bind_name(sym.bind),
            type=_type_name(sym.type),
            section=_sec_name(elf, sym.shndx),
        )
        out.append(e)
    out.sort(key=lambda x: x.addr)
    return out


def collect_imports(elf: ELFReader, resolver: ImportResolver):
    out = []
    versym = elf.versym
    version_names = {}
    for lib, entries in (elf.version_need or {}).items():
        for vnum, name, _flags in entries:
            if vnum:
                version_names[vnum] = name

    for sym in elf.dynsym:
        if not sym.is_import:
            continue
        if not sym.name:
            continue
        if sym.name.startswith("_ITM_") or sym.name.startswith("_ZSt") or not sym.name:
            pass
        ver = ""
        if versym and sym.index < len(versym):
            v = versym[sym.index]
            idx = v & 0x7FFF
            if idx and idx in version_names:
                ver = version_names[idx]
        out.append(ImportEntry(name=sym.name, version=ver))
    return out


def analyse_security(elf: ELFReader):
    """Return a dict of security/fortification related observations."""
    out = {}
    out["soname"] = elf.soname
    out["needed"] = elf.needed
    flags = elf.flags or 0
    out["bind_now"] = bool(flags & 0x1)
    out["pie"] = elf.pie
    out["e_flags"] = elf.e_flags
    out["android_min_api"] = elf.android_api
    out["build_id"] = elf.build_id()

    # Hardening heuristics (based on symbol presence).
    sym_names = {s.name for s in elf.dynsym}
    out["has_stack_protector"] = "__stack_chk_fail" in sym_names
    out["has_fortify"] = any(n.startswith("__") and "chk" in n for n in sym_names)
    out["has_relro"] = bool(elf.section_by_name(".relro_padding")) or any(
        s.name == ".dynamic" for s in elf.sections
    )
    return out


def find_executable_sections(elf: ELFReader):
    out = []
    for (lo, hi, name) in elf.exec_ranges():
        out.append({"name": name, "start": lo, "end": hi})
    return out