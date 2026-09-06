"""Disassembly engine.

Wraps capstone for ARM64, ARM (32), x86 and x86_64.  If capstone is not
available, disassembly degrades to a plain raw-byte dump so the rest of the
pipeline keeps working.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..elf.reader import ELFReader
from ..elf.arch import detect_arch

try:
    import capstone as _capstone
    HAVE_CAPSTONE = True
except Exception:  # pragma: no cover - environment dependent
    _capstone = None
    HAVE_CAPSTONE = False


@dataclass
class Insn:
    address: int
    size: int
    mnemonic: str
    op_str: str
    bytes: bytes
    groups: list = field(default_factory=list)

    @property
    def text(self):
        if self.op_str:
            return f"{self.mnemonic:<6} {self.op_str}"
        return self.mnemonic

    @property
    def is_ret(self):
        return self.mnemonic in ("ret", "retr", "bx", "poppc", "blr", "retq")

    def operands(self):
        """Simple whitespace/comma splitting of operand text."""
        if not self.op_str:
            return []
        parts = []
        for p in self.op_str.split(","):
            parts.append(p.strip())
        return parts


# ---------------------------------------------------------------------------
# Detailed disassembly: exposes resolved capstone operand structures so the
# decompiler can reason about register read/write, immediates and memory
# operands instead of parsing operand text with regexes.
# ---------------------------------------------------------------------------

CS_AC_READ = 2
CS_AC_WRITE = 1
CS_GRP_JUMP = 1
CS_GRP_CALL = 2
CS_GRP_RET = 3


@dataclass
class Operand:
    kind: str            # 'reg' | 'imm' | 'mem' | 'tex'
    reg: str = ""        # register name (kind='reg' or mem base/index)
    imm: int = 0         # immediate value (kind='imm' or mem disp)
    mem_base: str = ""   # kind='mem'
    mem_index: str = ""
    mem_disp: int = 0
    access: int = 0      # bitmask of CS_AC_READ / CS_AC_WRITE
    width: int = 0       # byte width for loads/stores (0 = n/a)
    text: str = ""       # kind='tex' (unparsed fallback)

    @property
    def is_read(self):
        return bool(self.access & CS_AC_READ)

    @property
    def is_write(self):
        return bool(self.access & CS_AC_WRITE)


@dataclass
class DetailedInsn:
    address: int
    size: int
    mnemonic: str
    op_str: str
    bytes: bytes
    operands: list
    groups: list = field(default_factory=list)

    @property
    def text(self):
        if self.op_str:
            return f"{self.mnemonic:<6} {self.op_str}"
        return self.mnemonic

    @property
    def is_jump(self):
        return CS_GRP_JUMP in self.groups

    @property
    def is_call(self):
        return CS_GRP_CALL in self.groups

    @property
    def is_ret(self):
        return CS_GRP_RET in self.groups or self.mnemonic == "ret"

    def reg(self, idx):
        """First operand that is a plain register, then the idx-th."""
        n = 0
        for o in self.operands:
            if o.kind == "reg":
                if n == idx:
                    return o.reg
                n += 1
        return None

    def is_writeback(self):
        return "!" in self.op_str


def _access_bits(o):
    try:
        return o.access
    except Exception:
        return CS_AC_READ | CS_AC_WRITE


def disassemble_detailed(elf: ELFReader, start: int, size: int):
    """Disassemble with capstone's operand API turned on.

    Returns a list of DetailedInsn with resolved register/immediate/memory
    operands.  Falls back to DetailedInsn with a single 'tex' operand when
    capstone is unavailable or disassembly fails.  Never raises.
    """
    import capstone as _cs_mod

    off = elf.addr_to_file(start)
    data = elf.bytes_at(off, size) if off is not None else b""
    if not data:
        return []
    config = get_cs_config(elf)
    if config is None:
        return _detailed_raw(start, data)
    carch, cmode = config
    try:
        md = _cs_mod.Cs(carch, cmode)
        md.detail = True
    except Exception:
        return _detailed_raw(start, data)

    out = []
    try:
        for insn in md.disasm(data, start):
            ops = []
            try:
                for o in insn.operands:
                    ops.append(_cap_op(md, o))
            except Exception:
                ops = []
            if not ops:
                ops = [Operand("tex", text=insn.op_str)]
            try:
                groups = list(insn.groups)
            except Exception:
                groups = []
            out.append(DetailedInsn(
                address=insn.address, size=insn.size, mnemonic=insn.mnemonic,
                op_str=insn.op_str, bytes=insn.bytes, operands=ops,
                groups=groups,
            ))
    except Exception:
        return _detailed_raw(start, data)
    return out


def get_cs_config(elf: ELFReader):
    from ..elf.arch import cs_config, detect_arch
    return cs_config(detect_arch(elf))


def _cap_op(md, o):
    try:
        otype = o.type
    except Exception:
        return Operand("tex", text=str(o))
    try:
        access = o.access
    except Exception:
        access = 0
    if otype == 1:  # reg
        name = _reg_name(md, o.reg)
        return Operand("reg", reg=name, access=access)
    if otype == 2:  # imm
        return Operand("imm", imm=getattr(o, "imm", 0), access=access)
    if otype == 3:  # mem
        m = o.mem
        try:
            base = _reg_name(md, m.base)
        except Exception:
            base = ""
        try:
            idxr = _reg_name(md, m.index) if m.index else ""
        except Exception:
            idxr = ""
        disp = getattr(m, "disp", 0)
        return Operand("mem", mem_base=base, mem_index=idxr,
                       mem_disp=disp, access=access)
    return Operand("tex", text=str(o))


def _reg_name(md, regid):
    if not regid:
        return ""
    try:
        name = md.reg_name(regid)
        return name or ""
    except Exception:
        return ""


def _detailed_raw(start, data):
    out = []
    for i in range(0, len(data), 4):
        chunk = data[i:i + 4].ljust(4, b"\x00")
        out.append(DetailedInsn(
            address=start + i, size=len(chunk), mnemonic=".byte",
            op_str=" ".join(f"{b:02x}" for b in chunk), bytes=chunk,
            operands=[Operand("tex", text=chunk.hex())],
        ))
    return out


def build_cs(elf: ELFReader):
    if not HAVE_CAPSTONE:
        return None
    arch = detect_arch(elf)
    config = None
    try:
        from ..elf.arch import cs_config
        config = cs_config(arch)
    except Exception:
        config = None
    if config is None:
        return None
    carch, cmode = config
    try:
        md = _capstone.Cs(carch, cmode)
        try:
            md.detail = True
        except Exception:
            pass
        return md
    except Exception:
        return None


def disassemble_range(elf: ELFReader, start: int, size: int, *, skip_data=0):
    """Disassemble `size` bytes at virtual address `start`.

    Returns a list of Insn.  Never raises; on failure returns a raw
    "byte_dump" pseudo-instruction list.
    """
    if size <= 0:
        return []
    off = elf.addr_to_file(start)
    if off is None:
        off = start  # assume direct file offset fallback
        data = elf.bytes_at(off, size)
    else:
        data = elf.bytes_at(off, size)
    if not data:
        return []

    cs = build_cs(elf)
    if cs is None:
        return _raw_insns(start, data)

    out = []
    try:
        for insn in cs.disasm(data, start):
            try:
                groups = list(insn.groups)
            except Exception:
                groups = []
            out.append(Insn(
                address=insn.address,
                size=insn.size,
                mnemonic=insn.mnemonic,
                op_str=insn.op_str,
                bytes=insn.bytes,
                groups=groups,
            ))
    except Exception:
        return _raw_insns(start, data)
    return out


def _raw_insns(start, data):
    out = []
    for i in range(0, len(data), 4):
        chunk = data[i:i + 4].ljust(4, b"\x00")
        out.append(Insn(
            address=start + i,
            size=len(chunk),
            mnemonic=".byte",
            op_str=" ".join(f"{b:02x}" for b in chunk),
            bytes=chunk,
        ))
    return out


def group_name(insn: Insn):
    """Return a short classification of an instruction."""
    m = insn.mnemonic
    if insn.is_ret:
        return "ret"
    if m in ("bl", "blx", "call", "calll"):
        return "call"
    if m in ("b", "br", "jmp"):
        return "branch"
    if m.startswith("b.") or m in ("cbz", "cbnz", "tbz", "tbnz", "je", "jne",
                                   "jz", "jnz", "ja", "jb", "jae", "jbe", "jg",
                                   "jge", "jl", "jle", "js", "jns", "jo", "jno",
                                   "jmp"):
        return "cond_jump"
    if m.startswith("bl"):
        return "call"  # blr handled above; but guard
    return "other"