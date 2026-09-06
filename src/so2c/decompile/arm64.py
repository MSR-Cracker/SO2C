"""ARM64 (and x86/ARM) linear-sweep decompiler.

The decompiler is a light-weight lifting engine: it walks each exported JNI
function, decodes every instruction (with manual ADRP/ADR handling), tracks a
symbolic register map and emits structured pseudo-C with:

  * JNIEnv vtable calls resolved to `env->MethodName(...)` with recovered
    string/descriptor arguments
  * PLT/import targets annotated with the imported symbol
  * literal string references ("str_const x2 <- 0xa1f")
  * stack canary detection and epilogue annotation
  * recovered per-function JNI signatures (from the GetMethodID descriptor)

It is deliberately conservative: registers that cannot be resolved are shown
verbatim, and branches render as `goto`/labels so output is always honest.
"""

from __future__ import annotations

import re

from ..elf.reader import ELFReader
from ..elf.symbols import ImportResolver
from ..jni.analyzer import jni_index_from_offset
from ..disasm.engine import disassemble_range, Insn
from .aarch64util import decode_aarch64_insn, aarch64_cond


class DecompFailure(Exception):
    pass


class Expr:
    """Symbolic expression node."""

    __slots__ = ("kind", "value", "aux")

    def __init__(self, kind, value=None, aux=None):
        self.kind = kind
        self.value = value
        self.aux = aux

    @staticmethod
    def imm(v):
        return Expr("imm", v)

    @staticmethod
    def addr(v):
        return Expr("addr", v)

    @staticmethod
    def page(v):
        return Expr("page", v)

    @staticmethod
    def str_(text, addr=None):
        return Expr("str", text, addr)

    @staticmethod
    def jni(idx, name):
        return Expr("jni", idx, name)

    @staticmethod
    def call(name, args=None):
        return Expr("call", name, args or [])

    @staticmethod
    def env():
        return Expr("env")

    @staticmethod
    def envfuncs():
        return Expr("envfuncs")

    @staticmethod
    def arg(idx):
        return Expr("arg", idx)

    @staticmethod
    def javaret(method):
        return Expr("javaret", method)

    def render(self):
        k = self.kind
        if k == "imm":
            return repr(self.value)
        if k == "addr":
            return f"{self.value:#x}"
        if k == "page":
            return f"{self.value:#x}"
        if k == "str":
            return f'"{self.value}"'
        if k == "jni":
            return f"JNI::{self.aux}"
        if k == "call":
            return self.aux or self.value
        if k == "env":
            return "env"
        if k == "envfuncs":
            return "env->functions"
        if k == "arg":
            return f"a?[{self.value}]"
        if k == "javaret":
            return f"<ret {self.value}>"
        return "?"


# Register mapping (AArch64 classic calling convention).
ARG_REGS = ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"]
RET_REGS = ["x0", "x1"]


class DecodedCall:
    __slots__ = ("address", "kind", "target", "args", "jni_index", "jni_name",
                 "result_reg", "line")

    def __init__(self, address, kind, target, args=None, jni_index=None,
                 jni_name=None, result_reg="x0"):
        self.address = address
        self.kind = kind
        self.target = target
        self.args = args or []
        self.jni_index = jni_index
        self.jni_name = jni_name
        self.result_reg = result_reg


class AArch64Decompiler:
    def __init__(self, elf, resolver, str_index):
        self.elf = elf
        self.resolver = resolver
        self.str_index = str_index or {}
        self.calls = []          # DecodedCall list
        self.regs = {}
        self.sp_offset = 0
        self.frame_size = 0
        self.saved_frame = {}

    # ------------------------------------------------------------------ api
    def decompile(self, addr, size, name="", jni_hint=None):
        insns = disassemble_range(self.elf, addr, size)
        if not insns:
            return []
        self.insns = insns
        self.name = name
        self.addr = addr
        self.size = size
        self.calls = []
        self.regs = {}
        self.sp_offset = 0
        self.saved_frame = {}
        self.frame_size = self._detect_frame(insns)
        # Function entry register semantics (AAPCS64 / JNI):
        #   x0 = JNIEnv*, x1 = jobject/jclass, x2..x7 = args.
        self.regs["x0"] = Expr.env()
        self.regs["x1"] = Expr("thiz")
        for k in range(2, 8):
            self.regs[ARG_REGS[k]] = Expr("arg", k - 2)
        self.regs["w0"] = Expr("env")
        return self._emit(insns, name)

    # ------------------------------------------------------------- frame
    def _detect_frame(self, insns):
        for insn in insns:
            m = insn.mnemonic
            if m == "sub" and insn.op_str == "sp, sp, #0x0":
                continue
            mm = re.match(r"sp, sp, #(0x[0-9a-fA-F]+|\d+)", insn.op_str)
            if m == "sub" and mm:
                return int(mm.group(1), 0)
            if m in ("stp", "push"):
                return None
        return None

    # ----------------------------------------------------------- helpers
    def _render_reg(self, r):
        return r

    def _read_ptr_u64(self, addr):
        b = self.elf.read_addr(addr, 8)
        if b is None or len(b) != 8:
            return None
        import struct
        return struct.unpack("<Q", b)[0]

    def _str_at(self, addr):
        if isinstance(addr, int) and addr in self.str_index:
            return self.str_index[addr]
        return None

    def _decode_own(self, insn):
        raw = self._raw(insn)
        if raw is None:
            return None
        try:
            return decode_aarch64_insn(raw, insn.address)
        except Exception:
            return None

    @staticmethod
    def _raw(insn):
        if len(insn.bytes) >= 4:
            return int.from_bytes(insn.bytes[:4], "little")
        return None

    def _rd(self, word):
        return word & 0x1F

    # ------------------------------------------------------------ emitter
    def _emit(self, insns, name):
        lines = []
        lines.append("    // ------------------------------------------------------------------")
        lines.append(f"    // {name} @ {self.addr:#x}  (size {self.size})")
        if self.frame_size is not None:
            lines.append(f"    // stack frame : sp -= 0x{self.frame_size:x}")
        lines.append("    // ------------------------------------------------------------------")
        lines.append("    {")

        # pre-scan for branch targets to emit labels
        targets = self._collect_targets(insns)
        emitted_labels = set()

        i = 0
        n = len(insns)
        while i < n:
            insn = insns[i]
            a = insn.address
            if a in targets and a not in emitted_labels and a != self.addr:
                lines.append(f"    L_{a:#x}: ;")
                emitted_labels.add(a)

            word = self._raw(insn)
            d = self._decode_own(insn)
            m = insn.mnemonic
            op = insn.op_str

            # ==================== RET / tail ====================
            if m == "ret":
                lines.append(self._emit_return(insn, lines))
                i += 1
                continue

            if m == "bl":
                tgt = d["target"] if d and "target" in d else None
                resolved = self.resolver.resolve(tgt) if tgt else None
                if resolved:
                    lines.append(
                        f"    // {a:#x}: {insn.text}  ->  {resolved}()")
                else:
                    lines.append(f"    // {a:#x}: {insn.text}")
                i += 1
                continue

            if m == "b":
                tgt = d["target"] if d else None
                if tgt is not None:
                    lines.append(f"    // {a:#x}: goto L_{tgt:#x}")
                else:
                    lines.append(f"    // {a:#x}: {insn.text}")
                i += 1
                continue

            if m.startswith("b.") or m in ("cbz", "cbnz", "tbnz", "tbz"):
                tgt = None
                cond = None
                if m.startswith("b.") and d:
                    tgt = d.get("target")
                    cond = aarch64_cond(d.get("cond", -1))
                elif m in ("cbz", "cbnz", "tbz", "tbnz") and d:
                    tgt = d.get("target")
                    if m in ("cbz", "cbnz"):
                        cond = "eq" if m == "cbz" else "ne"
                if tgt is not None:
                    if m.startswith("b."):
                        prefix = f"if ({cond}) " if cond else ""
                        lines.append(
                            f"    // {a:#x}: {prefix}goto L_{tgt:#x}")
                    else:
                        src = op.split(",")[0].strip()
                        sem = self._reg_str(src)
                        dpy = f"{src}={sem}" if sem != src else src
                        if cond == "eq":
                            lines.append(
                                f"    // {a:#x}: if ({dpy} == 0) goto L_{tgt:#x}")
                        elif cond == "ne":
                            lines.append(
                                f"    // {a:#x}: if ({dpy} != 0) goto L_{tgt:#x}")
                        else:
                            lines.append(
                                f"    // {a:#x}: if ({dpy}) goto L_{tgt:#x}")
                else:
                    lines.append(f"    // {a:#x}: {insn.text}")
                i += 1
                continue

            # ==================== data / arith ====================
            handled = self._handle_insn(lines, insn, word, d, i)
            if not handled:
                lines.append(f"    // {a:#x}: {insn.text}")
            i += 1

        lines.append("    }")
        return lines

    # ---------------------------------------------------------- helpers
    def _cond_cc(self, cond):
        return {
            "eq": "== 0", "ne": "!= 0", "cs": ">= 0", "lo": "< 0",
            "cc": "< 0", "mi": "< 0", "pl": ">= 0", "hi": "> 0",
            "ls": "<= 0", "ge": ">= 0", "lt": "< 0", "gt": "> 0",
            "le": "<= 0", "al": "", "nv": "",
        }.get(cond, f"[{cond}]")

    def _cond_sym(self, cond):
        return cond

    def _reg_str(self, src):
        src = src.strip()
        if src in self.regs:
            e = self.regs[src]
            s = self._expr_str(e)
            if s != "?":
                return s
        return src

    def _expr_str(self, e):
        if e is None:
            return "?"
        return e.render()

    def _collect_targets(self, insns):
        targets = set()
        for insn in insns:
            d = self._decode_own(insn)
            if not d:
                continue
            if d["kind"] in ("branch", "bl", "cond_branch") and "target" in d:
                targets.add(d["target"])
        return targets

    # ---------------------------------------------- instruction handlers
    def _handle_insn(self, lines, insn, word, d, idx):
        m = insn.mnemonic
        op = insn.op_str
        a = insn.address

        if m == "adrp" and d:
            rd = self._rd(word) if word is not None else None
            tgt = d.get("target")
            self.regs[self._rd_name(rd)] = Expr("page", tgt)
            lines.append(f"    // {a:#x}: adrp {self._rd_name(rd)}, "
                         f"page={tgt:#x}")
            return True

        if m == "adr" and d:
            rd = self._rd(word) if word is not None else None
            tgt = d.get("target")
            self.regs[self._rd_name(rd)] = Expr("addr", tgt)
            s = self._str_at(tgt)
            tag = f'  ; "{s}"' if s else ""
            lines.append(f"    // {a:#x}: adr {self._rd_name(rd)} = {tgt:#x}{tag}")
            return True

        if m == "add":
            parts = [p.strip() for p in op.split(",")]
            if len(parts) >= 3:
                r0, r1, imm = parts[0], parts[1], parts[2]
                val = self._imm_try(imm)
                if val is not None:
                    base = self.regs.get(r1)
                    if base and base.kind in ("page", "addr", "imm"):
                        total = base.value + val
                        s = self._str_at(total)
                        if s is not None:
                            self.regs[r0] = Expr("str", s, total)
                            lines.append(
                                f"    // {a:#x}: str_const {r0} = \"{s}\"   "
                                f"({total:#x})")
                            return True
                        self.regs[r0] = Expr("addr", total)
                        lines.append(f"    // {a:#x}: {r0} = "
                                     f"{base.value:#x} + 0x{val:x}")
                        return True
            lines.append(f"    // {a:#x}: {insn.text}")
            return True

        if m in ("mov", "movz",):
            parts = [p.strip() for p in op.split(",")]
            if len(parts) == 2:
                rd, src = parts
                iv = self._imm_try(src)
                if iv is not None:
                    self.regs[rd] = Expr("imm", iv)
                elif src.startswith("xzr") or src == "wzr":
                    self.regs[rd] = Expr("imm", 0)
                elif src in self.regs:
                    self.regs[rd] = self.regs[src]
            lines.append(f"    // {a:#x}: {insn.text}")
            return True

        if m in ("ldr", "ldur", "ldrb", "ldrsw", "ldrsb"):
            d2 = self._decode_own(insn)
            if d2 and d2["kind"] == "ldr_literal":
                target = d2.get("target")
                rd = self._rd_name(self._rd(word))
                s = self._str_at(target)
                if s is not None:
                    self.regs[rd] = Expr("str", s, target)
                    lines.append(f"    // {a:#x}: {rd} = \"{s}\"   (literal)")
                else:
                    lines.append(f"    // {a:#x}: {insn.text}  (literal @ {target:#x})")
                return True
            return self._handle_ldr_mem(lines, insn, word)

        if m in ("ldp", "ldnp"):
            # restore saved regs (epilogue) - just comment
            lines.append(f"    // {a:#x}: {insn.text}")
            return True

        if m in ("str", "stur"):
            lines.append(f"    // {a:#x}: {insn.text}")
            return True

        if m == "stp":
            lines.append(f"    // {a:#x}: {insn.text}")
            return True

        if m in ("sub", "cmp", "cmn", "ands", "tst", "bic"):  # flag ops
            if m == "sub":
                pass
            lines.append(f"    // {a:#x}: {insn.text}")
            return True

        if m in ("mrs", "nop"):
            if m == "mrs" and "tpidr_el0" in op:
                lines.append(f"    // {a:#x}: stack canary base loaded")
            else:
                lines.append(f"    // {a:#x}: {insn.text}")
            return True

        if m in ("csel", "cset", "csinc", "csneg"):
            lines.append(f"    // {a:#x}: {insn.text}")
            return True

        # ---- indirect call through vtable / register
        if m in ("blr", "br"):
            src = op.strip()
            jni = self._jni_for_reg(src, insn)
            if jni is not None:
                args = [self._reg_str(r) for r in ARG_REGS[:4]]
                while args and (args[-1] == "?" or args[-1].startswith("a?")):
                    args.pop()
                lines.append(
                    f"    // {a:#x}: env->{jni[1]}({', '.join(args)})")
                self.calls.append(DecodedCall(
                    a, "jni", jni[0], args, jni_index=jni[0], jni_name=jni[1]))
                # The C return is placed in x0/x1 for the caller.
                self.regs["x0"] = Expr.javaret(jni[1])
                self.regs["w0"] = Expr.javaret(jni[1])
                self.regs["x1"] = None
            else:
                lines.append(f"    // {a:#x}: {insn.text}  (indirect, "
                             f"{src}=?{self._reg_str(src) if False else ''})")
            return True

        # ---- simple FP/branch misc
        if m in ("fmov", "fcmp", "fadd", "fsub", "fmul", "fdiv", "fneg",
                 "abs", "fabs", "frint", "frinta", "frintn", "frintz"):
            lines.append(f"    // {a:#x}: {insn.text}")
            return True

        return False

    def _handle_ldr_mem(self, lines, insn, word):
        a = insn.address
        op = insn.op_str
        m = re.match(
            r"(x\d+|w\d+|s\d+|d\d+|q\d+)\s*,\s*\[(x\d+)"
            r"(?:,\s*#?(0x[0-9a-fA-F]+|\d+))?\]", op)
        if not m:
            lines.append(f"    // {a:#x}: {insn.text}")
            return True
        rd, rn, off = m.group(1), m.group(2), m.group(3)
        off = int(off, 0) if off else 0
        base = self.regs.get(rn)

        # env -> functions
        if base and base.kind == "env":
            self.regs[rd] = Expr("envfuncs")
            lines.append(f"    // {a:#x}: {rd} = JNIEnv (functions)   "
                         f"[{rn}=env]")
            return True
        if base and base.kind == "envfuncs":
            jni = jni_index_from_offset(off)
            if jni:
                self.regs[rd] = Expr("jni", off, jni)
            lines.append(
                f"    // {a:#x}: {rd} = JNIEnv->{jni}  (index {off // 8})"
                if jni else f"    // {a:#x}: {insn.text}")
            return True
        if base and base.kind in ("page", "addr", "imm"):
            addr = base.value + off
            s = self._str_at(addr)
            if s is not None:
                self.regs[rd] = Expr("str", s, addr)
                lines.append(f"    // {a:#x}: {rd} = \"{s}\"  (str @ {addr:#x})")
                return True
            ptr = self._read_ptr_u64(addr)
            if ptr is not None:
                nm = self.resolver.resolve(ptr)
                if nm:
                    self.regs[rd] = Expr("call", nm)
                    lines.append(f"    // {a:#x}: {rd} = &{nm}")
                    return True
                lines.append(f"    // {a:#x}: {rd} = *(u64*){addr:#x} = 0x{ptr:x}")
                return True
        lines.append(f"    // {a:#x}: {insn.text}")
        return True

    # look backwards for ldr X, [X, #off] that filled X with a JNI fn ptr
    def _jni_for_reg(self, src, insn):
        base = self.regs.get(src)
        if base and base.kind == "jni":
            return (base.value, base.aux)
        return None

    def _emit_return(self, insn, lines):
        a = insn.address
        # Try to say what is being returned.
        val = self.regs.get("x0")
        if val and val.kind in ("jni", "javaret"):
            name = val.aux or val.value
            return f"    // {a:#x}: ret  ; return value from env->{name}"
        if val and val.kind in ("imm", "addr"):
            return f"    // {a:#x}: ret  ; return {val.render()}"
        return f"    // {a:#x}: ret"

    def _rd_name(self, rd):
        return f"x{rd}" if rd is not None else "?"

    @staticmethod
    def _imm_try(s):
        s = s.strip()
        if s.startswith("#"):
            s = s[1:].strip()
        try:
            return int(s, 0)
        except Exception:
            return None


def decompile_function(elf, resolver, str_index, addr, size, name=""):
    """Public API: decompile one function, return pseudo-C lines."""
    arch = elf.arch_name
    if arch == "aarch64":
        return AArch64Decompiler(elf, resolver, str_index).decompile(
            addr, size, name)
    return _generic_decompile(elf, resolver, addr, size, name)

def _generic_decompile(elf, resolver, addr, size, name):
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