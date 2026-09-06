"""Recover function locations from (possibly stripped) executable regions.

The dynamic symbol table only describes a few JNI entry points; dex2c and
real Android .so files also contain plain C helpers, ``JNI_OnLoad`` stubs,
callback dispatch routines, `atexit` hooks and so on.  ``discover_functions``
combs every executable PROGBITS section (excluding ``.plt``) and reconstructs
function boundaries with a recursive-descent + anchor algorithm:

1. seed known starts: exported FN symbols, ``RegisterNatives`` table pointers,
   ``.init_array``/``.fini_array`` entries, target of every in-region ``bl``,
   and pointer-sized slots in writable sections that point back into the
   region (callback tables);

2. anchor the region at those seeds (so interior ``ret``s / cold blocks stay
   inside their owning function — a function with several exits is one
   function, not N);

3. between anchors, run a recursive descent from each anchor restricted to the
   [anchor, next_anchor) window.  Addresses the anchor's own flow can never
   reach — that follow a ``ret``/``br``/tail-``b`` and still look like a
   function entry (``bti``, prologue, or any reasonable instruction) — are new
   basi seeds, iterated to a fixpoint;

4. emit ordered, non-overlapping, gap-free ``FuncInfo`` chunks; PLT stubs are
   listed separately for reference.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..disasm.engine import disassemble_detailed
from ..elf.symbols import collect_exports, ImportResolver

from .cfg import edge_kind_of, branch_target


@dataclass
class FuncInfo:
    """One recovered function."""
    addr: int
    size: int
    kind: str = "internal"        # exported | internal | init | fini | plt | jni_reg | call
    name: str = ""
    section: str = ""
    func_names: dict = field(default_factory=dict)  # addr -> sub_XXXX names

    @property
    def short_name(self) -> str:
        return self.name or self.func_names.get(self.addr) or f"sub_{self.addr:x}"


def _ptr_size(elf) -> int:
    return 8 if getattr(elf, "is64", True) else 4


def _read_ptrs(elf, sec):
    """Yield pointer-sized integers from a section's file bytes."""
    import struct
    p = _ptr_size(elf)
    data = elf.bytes_at(sec.offset, sec.size) if sec.offset else b""
    fmt = "<Q" if p == 8 else "<I"
    for i in range(0, len(data) - p + 1, p):
        yield struct.unpack_from(fmt, data, i)[0]


def _exec_regions(elf):
    out = []
    for lo, hi, name in elf.exec_ranges():
        if ".plt" in name:
            continue
        if hi > lo:
            out.append((lo, hi, name))
    return out


def _plausible_start(insn) -> bool:
    """An instruction that cannot open a real function."""
    if insn is None:
        return False
    if insn.mnemonic in ("ret", ".byte", ".data", ".word", ".long"):
        return False
    return True


def _is_nop_only(body) -> bool:
    return bool(body) and all(getattr(i, "mnemonic", "") == "nop" for i in body)


def _ends_flow(insn) -> bool:
    """True if `insn` (the instruction just before a candidate boundary)
    terminates flow so that a new function may legitimately start next.

    ``ret`` and ``br`` return indirectly; an unconditional ``b`` transfers
    control and never falls through — everything after it up to the next real
    start therefore sits behind a boundary (tail calls into .plt / other
    functions, or the dead bytes at the very end of a function)."""
    if insn is None:
        return False
    if insn.mnemonic in ("ret", "br"):
        return True
    return edge_kind_of(insn) == "jmp" and branch_target(insn) is not None


def _flow_closure(by, lo, start, end, seeds, resolver):
    """Return the set of instruction addresses reachable from `start` following
    intra-function control flow, never crossing into `seeds` or past `end`.

    ``ret`` / ``br`` / tail ``b``: flow ends (but the instruction address is
    still counted).  ``bl``/``blr``: call out — only the fallthrough continues.
    Conditional branches follow both the target and the fallthrough.
    """
    reached = set()
    work = [start]
    while work:
        a = work.pop()
        if a in reached or a < lo or a >= end:
            continue
        if a in seeds and a != start:
            continue
        insn = by.get(a)
        if insn is None:
            continue
        reached.add(a)
        ek = edge_kind_of(insn)
        if ek == "ret" or insn.mnemonic == "br":
            continue
        if ek == "jmp":
            t = branch_target(insn)
            if t is None:
                continue
            # tail call into .plt or into another known function: function ends
            if resolver.inside_plt(t) or t in seeds:
                continue
            if lo <= t < end:
                work.append(t)
            continue
        if ek == "cond":
            t = branch_target(insn)
            if t is not None and lo <= t < end and t not in seeds:
                work.append(t)
            nxt = a + insn.size
            work.append(nxt)
            continue
        if ek == "call":
            # do not enter the callee; fallthrough only
            if resolver.inside_plt(insn.address) or True:
                pass
            nxt = a + insn.size
            work.append(nxt)
            continue
        # fall / unknown
        nxt = a + insn.size
        work.append(nxt)
    return reached


def discover_functions(elf, resolver=None):
    """Return an ordered, non-overlapping list of FuncInfo for every .text-like
    executable region, plus one FuncInfo per .plt stub."""
    if resolver is None:
        resolver = ImportResolver(elf)
    regions = _exec_regions(elf)
    all_ranges = [(lo, hi) for lo, hi, _ in regions]

    exports = [e for e in collect_exports(elf)
               if e.type in ("FUNC", "NOTYPE")
               and any(lo <= e.addr < hi for lo, hi in all_ranges)]

    seeds = {}  # addr -> kind
    for e in exports:
        seeds[e.addr] = "exported"
    for lo, hi, _ in regions:
        seeds.setdefault(lo, "internal")

    try:
        from ..jni.analyzer import detect_jni_registration_tables
        for reg in detect_jni_registration_tables(elf):
            if reg.func_addr:
                seeds.setdefault(reg.func_addr, "jni_reg")
    except Exception:
        pass

    # .init_array / .fini_array / .preinit_array pointers.
    for sec in elf.sections:
        if sec.name in (".init_array", ".fini_array", ".preinit_array"):
            for v in _read_ptrs(elf, sec):
                if any(lo <= v < hi for lo, hi in all_ranges):
                    seeds.setdefault(v, sec.name[1:].split("_")[0])

    # Callback-table pointers: aligned pointer slots inside writable alloc
    # PROGBITS sections that point back into an executable region.
    for sec in elf.sections:
        if not sec.is_alloc or not sec.is_write or sec.type != 1:
            continue
        p = _ptr_size(elf)
        if sec.addr % p:
            continue
        for v in _read_ptrs(elf, sec):
            if any(lo <= v < hi for lo, hi in all_ranges):
                seeds.setdefault(v, "internal")

    # bl call targets that land inside an executable region.
    for lo, hi, _ in regions:
        for insn in disassemble_detailed(elf, lo, hi - lo):
            if insn.mnemonic in ("bl", "blx"):
                t = branch_target(insn)
                if t is not None and lo <= t < hi:
                    seeds.setdefault(t, "call")

    # ---- per-region anchored recursive-descent scan --------------------
    all_funcs = []
    for lo, hi, secname in regions:
        insns = disassemble_detailed(elf, lo, hi - lo)
        by = {i.address: i for i in insns}
        final = {a for a in seeds if lo <= a < hi}
        if not final:
            final = {lo}

        changed = True
        while changed:
            changed = False
            ordered = sorted(final)
            for idx, s in enumerate(ordered):
                end = ordered[idx + 1] if idx + 1 < len(ordered) else hi
                reached = _flow_closure(by, lo, s, end, final, resolver)
                # every 4-aligned address in (s, end) the anchor can never
                # reach is a possible new function start.
                for a in range(s + 4, end, 4):
                    if a in reached:
                        continue
                    if not _plausible_start(by.get(a)):
                        continue
                    prev = by.get(a - 4)
                    if a - 4 in reached:
                        # direct successor of the anchor's flow: boundary
                        # only if that flow really ended here.
                        if not _ends_flow(prev):
                            continue
                    else:
                        # interior of an unreached run: seed it only when the
                        # run begins exactly here, i.e. the instruction right
                        # before was itself an end-of-flow marker (otherwise
                        # the run's true start is earlier).
                        if not _ends_flow(prev):
                            continue
                    if a not in final:
                        final.add(a)
                        changed = True

        ordered = sorted(final)
        chunks = []
        for idx, s in enumerate(ordered):
            end = ordered[idx + 1] if idx + 1 < len(ordered) else hi
            chunks.append([s, end])

        # drop unlikely starts (lone ret already filtered) and pure-nop
        # padding chunks, folding leftover bytes into the previous function.
        kept = []
        prev = None
        for s, end in chunks:
            body = [by[x] for x in range(s, end, 4) if x in by]
            if _is_nop_only(body):
                if prev is not None:
                    prev[1] = max(prev[1], end)
                continue
            prev = [s, end]
            kept.append(prev)
        if kept:
            kept[-1][1] = hi

        for s, end in kept:
            e = next((x for x in exports if x.addr == s), None)
            f = FuncInfo(addr=s, size=end - s,
                         kind=seeds.get(s, "internal"),
                         name=e.name if e is not None else "",
                         section=secname)
            all_funcs.append(f)

    all_funcs.sort(key=lambda f: (f.addr, f.size))
    name_map = {f.addr: f.short_name for f in all_funcs}
    for f in all_funcs:
        f.func_names = name_map

    # ---- PLT stubs for reference --------------------------------------
    for a in sorted(resolver.plt_ranges):
        all_funcs.append(FuncInfo(addr=a, size=16, kind="plt",
                                  name=resolver.plt_ranges[a], section=".plt"))
    all_funcs.sort(key=lambda f: (f.addr, f.size))
    return all_funcs