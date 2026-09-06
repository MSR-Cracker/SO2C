"""JNI descriptor parsing shared by the decompiler and source generator."""

from __future__ import annotations

# descriptor char -> C type
_C_TYPE = {
    "Z": "jboolean", "B": "jbyte", "C": "jchar", "S": "jshort",
    "I": "jint", "J": "jlong", "F": "jfloat", "D": "jdouble",
    "L": "jobject", "[": "jobject", "V": "void",
}


def ret_type(desc: str) -> str:
    """Return C type for a JNI descriptor return char."""
    if not desc:
        return "void"
    if desc.startswith("["):
        return "jobject"
    return _C_TYPE.get(desc, "jobject")


def split_params(sig: str):
    """Split '(A;B;;...)...' into the parameter descriptor and return char."""
    if not sig:
        return "", ""
    if not sig.startswith("("):
        return "", ""
    end = sig.find(")")
    if end < 0:
        return sig[1:], ""
    return sig[1:end], sig[end + 1:]


def param_list(sig: str):
    """Return [(type, name)] for a JNI descriptor, or [] ."""
    params, _ = split_params(sig)
    out = []
    i = 0
    name = ord("a")
    while i < len(params):
        depth = 0
        while i < len(params) and params[i] == "[":
            depth += 1
            i += 1
        if i >= len(params):
            break
        c = params[i]
        if c == "L":
            j = params.find(";", i)
            if j < 0:
                j = len(params) - 1
            typ = "jobject"
            i = j + 1
        else:
            typ = ret_type(c)
            i += 1
        n = chr(name)
        name += 1
        if depth:
            typ = "jobject"
        out.append((typ, n))
    return out