"""Minimal, dependency-free ELF reader.

Supports ELF32/ELF64, little/big endian and the four Android ABIs
(x86, x86_64, armeabi-v7a/arm, arm64-v8a/aarch64).  Only the headers,
sections, segments, symbol tables, string tables, dynamic table,
relocations and notes that we actually need are exposed.
"""

from __future__ import annotations

import struct

ELF_MAGIC = b"\x7fELF"

EM_X86 = 3
EM_ARM = 40
EM_X86_64 = 62
EM_AARCH64 = 183

EM_NAMES = {
    EM_X86: "x86",
    EM_ARM: "arm",
    EM_X86_64: "x86_64",
    EM_AARCH64: "aarch64",
}

SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_HASH = 5
SHT_DYNAMIC = 6
SHT_NOTE = 7
SHT_NOBITS = 8
SHT_REL = 9
SHT_DYNSYM = 11

SHN_UNDEF = 0

STT_NOTYPE = 0
STT_OBJECT = 1
STT_FUNC = 2
STT_SECTION = 3
STT_FILE = 4

STB_LOCAL = 0
STB_GLOBAL = 1
STB_WEAK = 2

SHT_FLAGS_WRITE = 0x1
SHT_FLAGS_ALLOC = 0x2
SHT_FLAGS_EXEC = 0x4

DT_NEEDED = 1
DT_SONAME = 14
DT_FLAGS = 30
DT_JMPREL = 23

PF_X = 1
PF_W = 2
PF_R = 4


class ELFError(Exception):
    """Raised when the input is not a usable ELF file."""


class ELFSection:
    __slots__ = (
        "index", "name", "type", "flags", "addr", "offset",
        "size", "link", "info", "align", "ent_size", "data_bytes",
    )

    def __init__(self, index, name, type_, flags, addr, offset, size, link, info, align, entsz):
        self.index = index
        self.name = name
        self.type = type_
        self.flags = flags
        self.addr = addr
        self.offset = offset
        self.size = size
        self.link = link
        self.info = info
        self.align = align
        self.ent_size = entsz
        self.data_bytes = b""

    @property
    def data(self):
        return self.data_bytes

    @property
    def is_write(self):
        return bool(self.flags & SHT_FLAGS_WRITE)

    @property
    def is_alloc(self):
        return bool(self.flags & SHT_FLAGS_ALLOC)

    @property
    def is_exec(self):
        return bool(self.flags & SHT_FLAGS_EXEC)

    def __repr__(self):
        return f"<ELFSection {self.index}:{self.name} va={self.addr:#x} size={self.size:#x} off={self.offset:#x}>"


class ELFSegment:
    __slots__ = ("index", "type", "offset", "vaddr", "paddr", "filesz", "memsz", "flags", "align")

    def __init__(self, index, type_, offset, vaddr, paddr, filesz, memsz, flags, align):
        self.index = index
        self.type = type_
        self.offset = offset
        self.vaddr = vaddr
        self.paddr = paddr
        self.filesz = filesz
        self.memsz = memsz
        self.flags = flags
        self.align = align


class ELFSymbol:
    __slots__ = ("index", "name", "value", "size", "info", "other", "shndx")

    def __init__(self, index, name, value, size, info, other, shndx):
        self.index = index
        self.name = name
        self.value = value
        self.size = size
        self.info = info
        self.other = other
        self.shndx = shndx

    @property
    def bind(self):
        return self.info >> 4

    @property
    def type(self):
        return self.info & 0xF

    @property
    def is_func(self):
        return (self.info & 0xF) == STT_FUNC

    @property
    def is_object(self):
        return (self.info & 0xF) == STT_OBJECT

    @property
    def is_global(self):
        return (self.info >> 4) in (STB_GLOBAL, STB_WEAK)

    @property
    def is_local(self):
        return (self.info >> 4) == STB_LOCAL

    @property
    def is_defined(self):
        return self.shndx != SHN_UNDEF

    @property
    def is_import(self):
        return self.shndx == SHN_UNDEF

    def __repr__(self):
        kind = "g" if self.is_global else "l"
        return f"<ELFSymbol {kind} {self.name} va={self.value:#x} sz={self.size}>"


class ELFRelocation:
    __slots__ = ("offset", "info", "type", "sym_index", "addend")

    def __init__(self, offset, info, type_, sym_index, addend):
        self.offset = offset
        self.info = info
        self.type = type_
        self.sym_index = sym_index
        self.addend = addend

    def __repr__(self):
        return f"<ELFRela off={self.offset:#x} type={self.type} sym={self.sym_index} addend={self.addend}>"


class ELFNote:
    __slots__ = ("name", "type", "desc")

    def __init__(self, name, type_, desc):
        self.name = name
        self.type = type_
        self.desc = desc


class ELFReader:
    """Parsed view of an ELF binary.

    The reader is defensive: if a section/table is missing it returns empty
    structures instead of raising, so higher layers can degrade gracefully.
    """

    def __init__(self, data: bytes):
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise ELFError("expected bytes")
        self.data = bytes(data)
        if len(self.data) < 16 or self.data[:4] != ELF_MAGIC:
            raise ELFError("not an ELF file (bad magic)")
        self.elf_class = self.data[4]
        if self.elf_class == 1:
            self.is64 = False
        elif self.elf_class == 2:
            self.is64 = True
        else:
            raise ELFError(f"invalid ELF class {self.elf_class}")
        endianness = self.data[5]
        if endianness == 1:
            self.byteorder = "<"
        elif endianness == 2:
            self.byteorder = ">"
        else:
            raise ELFError(f"invalid byte order {endianness}")
        self.android_api = None
        self._parse_header()
        self._parse_sections()
        self._parse_segments()
        self._parse_symbols()
        self._parse_dynamic()
        self._parse_relocations()
        self._parse_notes()

    # --------------------------- header ---------------------------
    def _parse_header(self):
        e = self.data
        if self.is64:
            if len(e) < 64:
                raise ELFError("truncated ELF64 header")
            # e_type,e_machine,e_version,e_entry,e_phoff,e_shoff,e_flags,
            # e_ehsize,e_phentsize,e_phnum,e_shentsize,e_shnum,e_shstrndx
            values = struct.unpack_from(self.byteorder + "HHIQQQIHHHHHH", e, 16)
        else:
            if len(e) < 52:
                raise ELFError("truncated ELF32 header")
            values = struct.unpack_from(self.byteorder + "HHIIIIIHHHHHH", e, 16)
        (
            self.e_type, self.machine, _e_version, self.entry,
            self.ph_off, self.sh_off, self.e_flags,
            self.ehsize, self.phentsize, self.phnum,
            self.shentsize, self.shnum, self.shstrndx,
        ) = values
        self.arch_name = EM_NAMES.get(self.machine)
        if self.arch_name is None:
            raise ELFError(f"unsupported machine type {self.machine}")
        self.pie = self.e_type == 3

    # --------------------------- sections ---------------------------
    def _parse_sections(self):
        self.sections: list[ELFSection] = []
        if not self.sh_off or not self.shnum:
            return
        esz = 64 if self.is64 else 40
        fmt = "IIQQQQIIQQ" if self.is64 else "IIIIIIIIII"
        for i in range(self.shnum):
            raw = self.data[self.sh_off + i * esz:self.sh_off + (i + 1) * esz]
            if len(raw) < esz:
                break
            vals = struct.unpack_from(self.byteorder + fmt, raw)
            sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_align, sh_entsz = vals
            self.sections.append(
                ELFSection(i, "", sh_type, sh_flags, sh_addr, sh_offset,
                           sh_size, sh_link, sh_info, sh_align, sh_entsz)
            )
        self._by_name: dict[str, ELFSection] = {}
        self._by_addr: dict[int, ELFSection] = {}
        if self.shstrndx and self.shstrndx < len(self.sections):
            strtab = self.sections[self.shstrndx]
            esz = 64 if self.is64 else 40
            for sec in self.sections:
                raw = self.data[self.sh_off + sec.index * esz:
                                self.sh_off + (sec.index + 1) * esz]
                name_off = struct.unpack_from(self.byteorder + "I", raw, 0)[0] if len(raw) >= 4 else 0
                name = self._cstr_at(strtab.offset + name_off) or f".sec{sec.index}"
                # Normalize well-known names; keep exact otherwise.
                sec.name = name
        for s in self.sections:
            self._by_name[s.name] = s
            if s.is_alloc and s.size:
                self._by_addr[s.addr] = s

        # Cache section data blobs (NOBITS sections get zero-filled stubs).
        for s in self.sections:
            if s.type == SHT_NOBITS or s.size == 0:
                s.data_bytes = b""
            else:
                s.data_bytes = self.bytes_at(s.offset, min(s.size, len(self.data)))

    # --------------------------- segments ---------------------------
    def _parse_segments(self):
        self.segments: list[ELFSegment] = []
        if not self.ph_off or not self.phnum:
            return
        esz = 56 if self.is64 else 32
        fmt = "IIQQQQQQ" if self.is64 else "IIIIIIII"
        if self.phentsize < esz:
            esz = self.phentsize
        if esz <= 0:
            return
        for i in range(self.phnum):
            raw = self.data[self.ph_off + i * esz:self.ph_off + (i + 1) * esz]
            if len(raw) < esz:
                break
            vals = struct.unpack_from(self.byteorder + fmt, raw)
            t, off, vaddr, paddr, filesz, memsz, flags, align = vals
            self.segments.append(ELFSegment(i, t, off, vaddr, paddr, filesz, memsz, flags, align))

    # --------------------------- symbols ---------------------------
    def _parse_symbols(self):
        self.dynsym: list[ELFSymbol] = []
        self.symtab: list[ELFSymbol] = []
        self.dynstr: bytes = b""
        self.versym: list[int] = []
        self.version_need: dict[str, list] = {}

        dynsym = self._by_name.get(".dynsym")
        if dynsym:
            self._parse_symbol_table(dynsym, ".dynstr", self.dynsym)
            ds = self._by_name.get(".dynstr")
            self.dynstr = ds.data if ds else b""
        symtab = self._by_name.get(".symtab")
        if symtab:
            self._parse_symbol_table(symtab, ".strtab", self.symtab)

        gv = self._by_name.get(".gnu.version")
        if gv:
            n = gv.size // 2
            self.versym = list(struct.unpack_from(self.byteorder + f"{n}H", self.data, gv.offset))
        gn = self._by_name.get(".gnu.version_r")
        if gn:
            self._parse_version_need(gn)

    def _parse_symbol_table(self, sec: ELFSection, strtab_name, out):
        strtab = self._by_name.get(strtab_name)
        table = strtab.data if strtab else b""
        if not sec or sec.size == 0:
            return
        esz = sec.ent_size or (24 if self.is64 else 16)
        for i in range(sec.size // esz):
            raw = self.data[sec.offset + i * esz:sec.offset + (i + 1) * esz]
            if len(raw) < esz:
                break
            if self.is64:
                st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from(
                    self.byteorder + "IBBHQQ", raw
                )
            else:
                st_name, st_value, st_size, st_info, st_other, st_shndx = struct.unpack_from(
                    self.byteorder + "IIIBBH", raw
                )
            name = ""
            if st_name < len(table):
                end = table.find(b"\x00", st_name)
                if end < 0:
                    end = len(table)
                name = table[st_name:end].decode("utf-8", "replace")
            out.append(ELFSymbol(i, name, st_value, st_size, st_info, st_other, st_shndx))

    def _parse_version_need(self, sec: ELFSection):
        off = sec.offset
        end = sec.offset + sec.size
        self.version_need = {}
        while off + 16 <= end:
            vn_version, vn_cnt, vn_file, vn_aux, vn_next = struct.unpack_from(
                self.byteorder + "HHIII", self.data, off
            )
            if vn_version == 0:
                break
            file_str = self._cstr_at(off + vn_file)
            dynstr = self._by_name.get(".dynstr")
            aux = off + vn_aux
            entries = []
            for _ in range(vn_cnt):
                if aux + 16 > end:
                    break
                vna_hash, vna_flags, vna_other, vna_name, vna_next = struct.unpack_from(
                    self.byteorder + "IHHII", self.data, aux
                )
                base = dynstr.offset if dynstr else 0
                ver_name = self._cstr_at(base + vna_name) if dynstr else ""
                entries.append((vna_other >> 8, ver_name, vna_flags))
                if vna_next == 0:
                    break
                aux += vna_next
            self.version_need[file_str] = entries
            if vn_next == 0:
                break
            off += vn_next

    # --------------------------- dynamic ---------------------------
    def _parse_dynamic(self):
        self.dynamic: dict[int, int] = {}
        self.dynamic_entries: list[tuple[int, int]] = []
        sec = self._by_name.get(".dynamic")
        if sec is None:
            seg = next((s for s in self.segments if s.type == 2), None)
            if seg:
                sec = ELFSection(0, ".dynamic", SHT_DYNAMIC,
                                 SHT_FLAGS_WRITE | SHT_FLAGS_ALLOC,
                                 seg.vaddr, seg.offset, seg.filesz, 0, 0, 8,
                                 16 if self.is64 else 8)
            else:
                return
        esz = 16 if self.is64 else 8
        fmt = "QQ" if self.is64 else "II"
        for i in range(sec.size // esz):
            raw = self.data[sec.offset + i * esz:sec.offset + (i + 1) * esz]
            if len(raw) < esz:
                break
            tag, val = struct.unpack_from(self.byteorder + fmt, raw)
            if tag == 0:
                break
            self.dynamic[tag] = val
            self.dynamic_entries.append((tag, val))

    # --------------------------- relocations ---------------------------
    def _parse_relocations(self):
        self.relocs: list[ELFRelocation] = []      # RELATIVE/data relocs
        self.jmprel: list[ELFRelocation] = []      # PLT lazy-binding relocs

        dyn_rela = self.dynamic.get(7)   # DT_RELA -> not used directly here
        jmprel = self.dynamic.get(DT_JMPREL)

        for name in (".rela.dyn", ".rel.dyn"):
            sec = self._by_name.get(name)
            if sec:
                self._parse_reloc_section(sec, self.relocs)
        for name in (".rela.plt", ".rel.plt"):
            sec = self._by_name.get(name)
            if sec:
                self._parse_reloc_section(sec, self.jmprel)

    def _parse_reloc_section(self, sec: ELFSection, out):
        if not sec.ent_size:
            return
        is_rela = sec.type == SHT_RELA
        esz = 24 if self.is64 else (12 if is_rela else 8)
        for i in range(sec.size // sec.ent_size):
            raw = self.data[sec.offset + i * sec.ent_size:
                            sec.offset + (i + 1) * sec.ent_size]
            if len(raw) < sec.ent_size:
                break
            if self.is64:
                r_offset, r_info, r_addend = struct.unpack_from(self.byteorder + "QQq", raw)
                r_sym = r_info >> 32
                r_type = r_info & 0xFFFFFFFF
            else:
                if is_rela:
                    r_offset, r_info, r_addend = struct.unpack_from(self.byteorder + "IIi", raw)
                else:
                    r_offset, r_info = struct.unpack_from(self.byteorder + "II", raw)
                    r_addend = 0
                r_sym = r_info >> 8
                r_type = r_info & 0xFF
            out.append(ELFRelocation(r_offset, r_info, r_type, r_sym, r_addend))

    # --------------------------- notes ---------------------------
    def _parse_notes(self):
        self.notes: list[ELFNote] = []
        for sec in self.sections:
            if sec.type == SHT_NOTE:
                self._parse_note_section(sec)

    def _parse_note_section(self, sec: ELFSection):
        off = sec.offset
        end = sec.offset + sec.size
        while off + 12 <= end:
            namesz, descsz, ntype = struct.unpack_from(self.byteorder + "III", self.data, off)
            name = ""
            if namesz and off + 12 + namesz <= len(self.data):
                name = self.data[off + 12:off + 12 + namesz].rstrip(b"\x00").decode("utf-8", "replace")
            desc_off = off + 12 + ((namesz + 3) & ~3)
            desc = b""
            if descsz and desc_off + descsz <= len(self.data):
                desc = self.data[desc_off:desc_off + descsz]
            self.notes.append(ELFNote(name, ntype, desc))
            if name == "Android" and ntype == 1 and len(desc) >= 4:
                self.android_api = struct.unpack_from(self.byteorder + "I", desc, 0)[0]
            if descsz:
                next_off = desc_off + ((descsz + 3) & ~3)
            else:
                next_off = desc_off
            if next_off <= off:
                break
            off = next_off
        if self.android_api is None:
            self.android_api = None

    # --------------------------- helpers ---------------------------
    def _cstr_at(self, file_off, max_len=4096):
        if file_off < 0 or file_off >= len(self.data):
            return ""
        end = self.data.find(b"\x00", file_off, file_off + max_len)
        if end < 0:
            end = file_off + max_len
        raw = self.data[file_off:end]
        try:
            return raw.decode("utf-8", "replace")
        except Exception:
            return repr(raw)

    def section_by_name(self, name):
        return self._by_name.get(name)

    def section_containing_addr(self, addr):
        return self._by_addr.get(addr)

    def section_containing_offset(self, off):
        for s in self.sections:
            if s.offset <= off < s.offset + s.size:
                return s
        return None

    def bytes_at(self, file_off, n):
        if file_off < 0 or file_off + n > len(self.data):
            return b""
        return self.data[file_off:file_off + n]

    def addr_to_file(self, addr):
        for s in self.sections:
            if s.is_alloc and s.addr <= addr < s.addr + s.size:
                return s.offset + (addr - s.addr)
        return None

    def file_to_addr(self, off):
        for s in self.sections:
            if s.is_alloc and s.offset <= off < s.offset + s.size:
                return s.addr + (off - s.offset)
        return None

    def read_addr(self, addr, n):
        off = self.addr_to_file(addr)
        if off is None:
            return None
        return self.bytes_at(off, n)

    def build_id(self):
        for note in self.notes:
            if note.name == "GNU" and note.type == 3:
                return note.desc.hex()
        return None

    @property
    def soname(self):
        soname_off = self.dynamic.get(DT_SONAME)
        if soname_off is None:
            return None
        dynstr = self._by_name.get(".dynstr")
        if dynstr is None:
            return None
        return self._cstr_at(dynstr.offset + soname_off)

    @property
    def needed(self):
        out = []
        dynstr = self._by_name.get(".dynstr")
        if dynstr is None:
            return out
        for tag, val in self.dynamic_entries:
            if tag == DT_NEEDED:
                out.append(self._cstr_at(dynstr.offset + val) or "?")
        return out

    @property
    def flags(self):
        return self.dynamic.get(DT_FLAGS)

    def exec_ranges(self):
        out = []
        for s in self.sections:
            if s.is_exec and s.is_alloc and s.type == SHT_PROGBITS:
                out.append((s.addr, s.addr + s.size, s.name))
        return out

    def text_range(self):
        text = self._by_name.get(".text")
        if text:
            return text.addr, text.addr + text.size
        return (0, 0)

    def gnu_hash_symbol(self, symtab_sec_name=".dynsym"):
        """Return dict mapping symbol name -> symbol for .dynsym."""
        return {s.name: s for s in self.dynsym if s.name}