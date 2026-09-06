"""Control-flow-graph recovery from a disassembly listing.

Basic blocks are split at function entry, at branch terminators (b, b.*, cbz,
cbnz, tbz, tbnz, br, ret), and at instruction-stream edges.  Fall-through and
explicit edges are recorded so structured emission can reconstruct branches
and labels.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Block:
    start: int                        # first address
    end: int                          # address just past last insn
    insns: list = field(default_factory=list)
    succ: list = field(default_factory=list)   # block start addrs we jump to
    terminal: str = "fall"            # fall | jmp | cond | ret | call | br

    @property
    def last(self) -> int:
        if self.insns:
            return self.insns[-1].address
        return self.start


def edge_kind_of(insn) -> str:
    m = insn.mnemonic
    if m == "ret":
        return "ret"
    if m == "br":
        return "br"
    if m == "b":
        return "jmp"
    if m in ("cbz", "cbnz", "tbz", "tbnz"):
        return "cond"
    if m.startswith("b."):
        return "cond"
    if m in ("blr", "bl"):
        return "call"
    return "fall"


def branch_target(insn) -> int | None:
    """Compute target address for unconditional/conditional branches."""
    m = insn.mnemonic
    if m in ("b", "bl"):
        for o in insn.operands:
            if o.kind == "imm":
                return o.imm
    if m.startswith("b.") or m in ("cbz", "cbnz", "tbz", "tbnz"):
        for o in insn.operands:
            if o.kind == "imm":
                return o.imm
    return None


def build_cfg(insns):
    """Return ordered list of Block objects covering `insns`."""
    if not insns:
        return []
    addr_to_idx = {i.address: idx for idx, i in enumerate(insns)}

    # Determine block split points.
    leaders = {insns[0].address}
    for i in insns:
        ek = edge_kind_of(i)
        if ek in ("jmp", "cond", "ret", "br"):
            t = branch_target(i)
            if t is not None and t in addr_to_idx:
                leaders.add(t)
            # fall-through edge starts a new block
            ni = addr_to_idx.get(i.address)
            if ni is not None and ni + 1 < len(insns):
                nxt = insns[ni + 1].address
                if ek in ("jmp", "cond", "ret", "br"):
                    leaders.add(nxt)
            elif ek in ("jmp", "cond", "ret", "br"):
                # past the last insn - no new block
                pass

    all_addrs = [i.address for i in insns]
    sorted_leaders = sorted(leaders)
    blocks = []
    for li, lead in enumerate(sorted_leaders):
        end = sorted_leaders[li + 1] if li + 1 < len(sorted_leaders) else \
            all_addrs[-1] + 4
        blk_insns = []
        for i in insns:
            if lead <= i.address < end:
                blk_insns.append(i)
        if not blk_insns:
            continue
        blocks.append(Block(start=lead, end=end, insns=blk_insns))

    # Fill successors.
    by_addr = {b.start: b for b in blocks}
    end_map = {insns[-1].address: None}
    for b in blocks:
        last = b.last
        rel = addr_to_idx.get(last)
        if rel is None:
            continue
        ek = edge_kind_of(insns[rel])
        succ = []
        if ek in ("jmp", "cond"):
            t = branch_target(insns[rel])
            if t in by_addr:
                succ.append(t)
        if ek in ("fall", "cond") :
            # fall-through
            nxt = last + insns[rel].size
            # only if within a block leader
            if nxt in by_addr:
                succ.append(nxt)
        if ek == "call":
            t = branch_target(insns[rel])
            if t in by_addr:
                succ.append(t)
            nxt = last + insns[rel].size
            if nxt in by_addr:
                succ.append(nxt)
        b.succ = succ

    return blocks


def linear_addrs(blocks) -> list[int]:
    return [b.start for b in blocks]
