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