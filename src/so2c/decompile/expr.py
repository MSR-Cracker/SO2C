"""Expression model for the decompiler.

Every value flowing through registers or stack slots is represented as an
Expr node.  Expressions are lightweight dicts with a 'k' (kind) tag so they
can be cheaply compared, hashed and rendered to C-like pseudocode.
"""

from __future__ import annotations


def imm(v: int) -> dict:
    return {"k": "imm", "v": v}


def fimm(v: float) -> dict:
    return {"k": "fimm", "v": v}


def reg(name: str) -> dict:
    return {"k": "reg", "v": name}


def env() -> dict:
    return {"k": "env"}


def envfn() -> dict:
    return {"k": "envfn"}


def jnifn(idx: int, name: str) -> dict:
    return {"k": "jnifn", "v": idx, "n": name}


def string(text: str, addr: int = 0) -> dict:
    return {"k": "str", "v": text, "a": addr}


def sym(name: str) -> dict:
    return {"k": "sym", "v": name}


def mem(base, offset: int, width: int) -> dict:
    return {"k": "mem", "b": base, "o": offset, "w": width}


def var(name: str) -> dict:
    return {"k": "var", "v": name}


def param(idx: int, name: str = "") -> dict:
    return {"k": "param", "v": idx, "n": name}


def call(target, args: list = None, type_: str = "void") -> dict:
    return {"k": "call", "v": target, "a": args or [], "t": type_}


def addr_of(inner) -> dict:
    return {"k": "addr", "v": inner}


def binop(op: str, left, right) -> dict:
    return {"k": "bin", "op": op, "l": left, "r": right}


def cast(type_: str, inner) -> dict:
    return {"k": "cast", "t": type_, "e": inner}


def unknown() -> dict:
    return {"k": "unk"}


def is_const(e, v=None) -> bool:
    if not isinstance(e, dict):
        return False
    if e.get("k") != "imm":
        return False
    if v is not None:
        return e.get("v") == v
    return True


def render(e) -> str:
    if not isinstance(e, dict):
        return str(e) if e is not None else "?"
    k = e["k"]
    if k == "imm":
        v = e["v"]
        if v < 0:
            return f"-0x{-v:x}"
        if v > 0x7FFFFFFF:
            return f"0x{v:x}"
        return str(v)
    if k == "fimm":
        v = e["v"]
        if v == 0.0:
            return "0.0f"
        return repr(v)
    if k == "reg":
        return e["v"]
    if k == "env":
        return "env"
    if k == "envfn":
        return "env->functions"
    if k == "jnifn":
        return f"env->{e['n']}"
    if k == "str":
        return f'"{e["v"]}"'
    if k == "sym":
        return e["v"]
    if k == "var":
        return e["v"]
    if k == "param":
        n = e.get("n", "")
        if n:
            return n
        return f"param{e['v']}"
    if k == "call":
        fn = render(e["v"]) if isinstance(e["v"], dict) else str(e["v"])
        args = ", ".join(render(a) for a in e["a"])
        return f"{fn}({args})"
    if k == "addr":
        inner = e["v"]
        if isinstance(inner, dict) and inner.get("k") == "var":
            return f"&{inner['v']}"
        return f"&({render(inner)})"
    if k == "bin":
        return f"({render(e['l'])} {e['op']} {render(e['r'])})"
    if k == "cast":
        return f"({e['t']})({render(e['e'])})"
    if k == "unk":
        return "/* ??? */"
    if k == "mem":
        base = e["b"]
        off = e["o"]
        w = e["w"]
        tname = {1: "u8", 2: "u16", 4: "u32", 8: "u64"}.get(w, f"u{w*8}")
        if isinstance(base, dict) and base.get("k") == "var":
            if off == 0:
                return base["v"]
            return f"{base['v']}[{off}]"
        if base is None:
            return f"*({tname}*)(0x{off:x})"
        return f"*({tname}*)({render(base)} + 0x{off:x})"
    return "?"


def kind_of(e) -> str:
    if isinstance(e, dict):
        return e.get("k", "")
    return ""


def value_of(e):
    if isinstance(e, dict):
        return e.get("v")
    return None
