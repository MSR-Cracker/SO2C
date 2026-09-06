"""ARM64 (and x86/ARM) decompiler — thin delegate to the real lifting engine.

This module used to contain a monolithic linear-sweep AArch64 decompiler.  It
now delegates all AArch64 work to :mod:`decompile.lift` which performs proper
value tracking, JNI call recovery, canary detection, phi notes, etc.

The public API (``decompile_function``, ``DecompFailure``, ``Expr``) is kept
for backward-compatibility with ``generate_c.py`` and any external callers.
"""

from __future__ import annotations

from .lift import Lift, DecompFailure, decompile_aarch64


def decompile_function(elf, resolver, str_index, addr, size, name="",
                       func_names=None, entry_env=None, jni_hint=None):
    """Public API: decompile one function, return pseudo-C lines.

    ``func_names`` is an {address: sub_XXXX} map used to name tail calls into
    other recovered functions; ``entry_env`` selects the JNI ABI binding (True
    for exported JNI methods, False for internal functions whose argument
    registers are not known).
    """
    arch = elf.arch_name
    if arch == "aarch64":
        return decompile_aarch64(elf, resolver, str_index, addr, size, name,
                                 jni_hint, func_names=func_names,
                                 entry_env=entry_env)
    return _generic_decompile(elf, resolver, str_index, addr, size, name)


def _generic_decompile(elf, resolver, str_index, addr, size, name):
    from ..disasm.engine import disassemble_range
    insns = disassemble_range(elf, addr, size)
    lines = [f"    // {name} @ {addr:#x}"]
    for insn in insns:
        m = insn.mnemonic
        if m in ("call", "bl", "blx"):
            tgt = _call_target(insn, resolver)
            if tgt:
                lines.append(f"    // {insn.address:#x}: -> {tgt}()")
            else:
                lines.append(f"    // {insn.address:#x}: call")
            continue
        lines.append(f"    // {insn.address:#x}: {insn.text}")
    return lines


def _call_target(insn, resolver):
    try:
        t = int(insn.op_str.strip(), 16)
        nm = resolver.resolve(t)
        return nm or f"0x{t:x}"
    except Exception:
        return None
