"""AArch64-specific machine-code helpers.

Provides manual resolution of ADR/ADRP page-relative addressing, literal
loads, and branch targets because capstone (v5) does not always expose the
resolved target for adrp/adr and literal-pool loads in its op_str.
"""

from __future__ import annotations

import struct


def decode_aarch64_insn(word: int, addr: int):
    """Decode the raw 32-bit AArch64 word at virtual address `addr`.

    Returns a dict describing addressing semantics we care about:
      kind: "adr" | "adrp" | "ldr_literal" | "branch" | "cond_branch" |
            "bl" | "other"
      target: resolved virtual address (for adr/adrp/ldr_literal/branch)
      label: mnemonic-ish label for x/SP
    """
    # Branch (b): 0x14000000, bl: 0x94000000, br/blr: 0xd61f0000
    imm26 = word & 0x03FFFFFF
    if word & 0xFC000000 == 0x14000000:      # B
        target = addr + _sign_extend(imm26, 26) * 4
        return {"kind": "branch", "target": target}
    if word & 0xFC000000 == 0x94000000:      # BL
        target = addr + _sign_extend(imm26, 26) * 4
        return {"kind": "bl", "target": target}

    # CBZ/CBNZ (0xB4000000): imm19 << 2
    if word & 0x7E000000 == 0x34000000:      # CBZ/CBNZ base
        imm19 = (word >> 5) & 0x7FFFF
        target = addr + _sign_extend(imm19, 19) * 4
        return {"kind": "cond_branch", "target": target}
    # TBZ/TBNZ (0x36000000)
    if word & 0x7E000000 == 0x36000000:
        imm14 = (word >> 5) & 0x3FFF
        target = addr + _sign_extend(imm14, 14) * 4
        return {"kind": "cond_branch", "target": target}

    # B.cond (0x54000000): imm19<<2
    if word & 0xFF000010 == 0x54000000:
        imm19 = (word >> 5) & 0x7FFFF
        target = addr + (_sign_extend(imm19, 19)) * 4
        cond = word & 0xF
        return {"kind": "cond_branch", "target": target, "cond": cond}

    # ADRP (0x90000000): immhi:immlo forms a 21-bit signed page offset
    if word & 0x9F000000 == 0x90000000:
        immlo = (word >> 29) & 0x3
        immhi = (word >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        page = (addr >> 12) << 12
        target = (page + (_sign_extend(imm, 21) << 12)) & 0xFFFFFFFFFFF
        return {"kind": "adrp", "target": target, "reg": (word >> 0) & 0x1F if False else _rd(word)}

    # ADR (0x10000000)
    if word & 0x9F000000 == 0x10000000:
        immlo = (word >> 29) & 0x3
        immhi = (word >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        target = (addr + _sign_extend(imm, 21)) & 0xFFFFFFFFFFF
        return {"kind": "adr", "target": target, "reg": _rd(word)}

    # Literal loads: LDR (literal) 0x18000000/0x1C..., LDRSW 0x98000000.
    hi = word >> 24
    if hi in (0x18, 0x1C, 0x98, 0x9C, 0xD8):
        imm19 = (word >> 5) & 0x7FFFF
        target = addr + _sign_extend(imm19, 19) * 4
        return {"kind": "ldr_literal", "target": target, "reg": _rd(word)}

    return {"kind": "other", "word": word}


def _rd(word):
    return (word >> 0) & 0x1F


_REG_ARM64 = [
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
    "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
    "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
    "x24", "x25", "x26", "x27", "x28", "x29", "x30", "sp",
]


def reg_name_arm64(r):
    if 0 <= r < 32:
        return _REG_ARM64[r]
    return f"x{r}"


def reg_name_arm64_w(r):
    return "w" + reg_name_arm64(r)[1:]


def _sign_extend(value, bits):
    sign = 1 << (bits - 1)
    return (value & (sign - 1)) - (value & sign)


def read_u32_le(data, off):
    if off + 4 > len(data):
        return None
    return struct.unpack_from("<I", data, off)[0]


def read_u64_le(data, off):
    if off + 8 > len(data):
        return None
    return struct.unpack_from("<Q", data, off)[0]


def aarch64_cond(cond):
    names = ["eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
             "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"]
    if 0 <= cond < 16:
        return names[cond]
    return "?"


# --------------------------------------------------------------------------
# x86 / x86_64 and ARM32 helpers (used by the shifters that resolve literal
# operands for those arches too). Keep minimal.
# --------------------------------------------------------------------------

X86_REGS32 = [
    "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
]
X86_REGS = X86_REGS32
X86_64_REGS = [
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
]


def reg_name_x86(r, is64):
    table = X86_64_REGS if is64 else X86_REGS32
    if 0 <= r < len(table):
        return table[r]
    return f"?{r}"


def reg_name_arm(r):
    if 0 <= r < 16:
        return f"r{r}"
    return f"?{r}"