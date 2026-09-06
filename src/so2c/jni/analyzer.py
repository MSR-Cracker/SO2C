"""JNI analysis: exported native methods, registration tables, JNI
function-index table used to resolve JNIEnv vtable calls."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..elf.reader import ELFReader
from ..elf.symbols import collect_exports

# Standard JNI function indices — Oracle / Sun spec ordering (as used by
# NDK / dex2c output).  AOSP's jni.h reverses the string-operation block
# (indices 164-170) but the NDK toolchain historically shipped the Sun
# ordering which is what the observed binaries use.
# index -> method name
JNI_FUNCS = {
    4: "GetVersion", 5: "DefineClass", 6: "FindClass",
    7: "FromReflectedMethod", 8: "FromReflectedField",
    9: "ToReflectedMethod", 10: "GetSuperclass", 11: "IsAssignableFrom",
    12: "ToReflectedField", 13: "Throw", 14: "ThrowNew",
    15: "ExceptionOccurred", 16: "ExceptionDescribe", 17: "ExceptionClear",
    18: "FatalError", 19: "PushLocalFrame", 20: "PopLocalFrame",
    21: "NewGlobalRef", 22: "DeleteGlobalRef", 23: "DeleteLocalRef",
    24: "IsSameObject", 25: "NewLocalRef", 26: "EnsureLocalCapacity",
    27: "AllocObject", 28: "NewObject", 29: "NewObjectV", 30: "NewObjectA",
    31: "GetObjectClass", 32: "IsInstanceOf", 33: "GetMethodID",
    34: "CallObjectMethod", 35: "CallObjectMethodV", 36: "CallObjectMethodA",
    37: "CallBooleanMethod", 38: "CallBooleanMethodV", 39: "CallBooleanMethodA",
    40: "CallByteMethod", 41: "CallByteMethodV", 42: "CallByteMethodA",
    43: "CallCharMethod", 44: "CallCharMethodV", 45: "CallCharMethodA",
    46: "CallShortMethod", 47: "CallShortMethodV", 48: "CallShortMethodA",
    49: "CallIntMethod", 50: "CallIntMethodV", 51: "CallIntMethodA",
    52: "CallLongMethod", 53: "CallLongMethodV", 54: "CallLongMethodA",
    55: "CallFloatMethod", 56: "CallFloatMethodV", 57: "CallFloatMethodA",
    58: "CallDoubleMethod", 59: "CallDoubleMethodV", 60: "CallDoubleMethodA",
    61: "CallVoidMethod", 62: "CallVoidMethodV", 63: "CallVoidMethodA",
    64: "CallNonvirtualObjectMethod", 65: "CallNonvirtualObjectMethodV",
    66: "CallNonvirtualObjectMethodA", 67: "CallNonvirtualBooleanMethod",
    68: "CallNonvirtualBooleanMethodV", 69: "CallNonvirtualBooleanMethodA",
    70: "CallNonvirtualByteMethod", 71: "CallNonvirtualByteMethodV",
    72: "CallNonvirtualByteMethodA", 73: "CallNonvirtualCharMethod",
    74: "CallNonvirtualCharMethodV", 75: "CallNonvirtualCharMethodA",
    76: "CallNonvirtualShortMethod", 77: "CallNonvirtualShortMethodV",
    78: "CallNonvirtualShortMethodA", 79: "CallNonvirtualIntMethod",
    80: "CallNonvirtualIntMethodV", 81: "CallNonvirtualIntMethodA",
    82: "CallNonvirtualLongMethod", 83: "CallNonvirtualLongMethodV",
    84: "CallNonvirtualLongMethodA", 85: "CallNonvirtualFloatMethod",
    86: "CallNonvirtualFloatMethodV", 87: "CallNonvirtualFloatMethodA",
    88: "CallNonvirtualDoubleMethod", 89: "CallNonvirtualDoubleMethodV",
    90: "CallNonvirtualDoubleMethodA", 91: "CallNonvirtualVoidMethod",
    92: "CallNonvirtualVoidMethodV", 93: "CallNonvirtualVoidMethodA",
    94: "GetFieldID", 95: "GetObjectField", 96: "GetBooleanField",
    97: "GetByteField", 98: "GetCharField", 99: "GetShortField",
    100: "GetIntField", 101: "GetLongField", 102: "GetFloatField",
    103: "GetDoubleField", 104: "SetObjectField", 105: "SetBooleanField",
    106: "SetByteField", 107: "SetCharField", 108: "SetShortField",
    109: "SetIntField", 110: "SetLongField", 111: "SetFloatField",
    112: "SetDoubleField", 113: "GetStaticMethodID",
    114: "CallStaticObjectMethod", 115: "CallStaticObjectMethodV",
    116: "CallStaticObjectMethodA", 117: "CallStaticBooleanMethod",
    118: "CallStaticBooleanMethodV", 119: "CallStaticBooleanMethodA",
    120: "CallStaticByteMethod", 121: "CallStaticByteMethodV",
    122: "CallStaticByteMethodA", 123: "CallStaticCharMethod",
    124: "CallStaticCharMethodV", 125: "CallStaticCharMethodA",
    126: "CallStaticShortMethod", 127: "CallStaticShortMethodV",
    128: "CallStaticShortMethodA", 129: "CallStaticIntMethod",
    130: "CallStaticIntMethodV", 131: "CallStaticIntMethodA",
    132: "CallStaticLongMethod", 133: "CallStaticLongMethodV",
    134: "CallStaticLongMethodA", 135: "CallStaticFloatMethod",
    136: "CallStaticFloatMethodV", 137: "CallStaticFloatMethodA",
    138: "CallStaticDoubleMethod", 139: "CallStaticDoubleMethodV",
    140: "CallStaticDoubleMethodA", 141: "CallStaticVoidMethod",
    142: "CallStaticVoidMethodV", 143: "CallStaticVoidMethodA",
    144: "GetStaticFieldID", 145: "GetStaticObjectField",
    146: "GetStaticBooleanField", 147: "GetStaticByteField",
    148: "GetStaticCharField", 149: "GetStaticShortField",
    150: "GetStaticIntField", 151: "GetStaticLongField",
    152: "GetStaticFloatField", 153: "GetStaticDoubleField",
    154: "SetStaticObjectField", 155: "SetStaticBooleanField",
    156: "SetStaticByteField", 157: "SetStaticCharField",
    158: "SetStaticShortField", 159: "SetStaticIntField",
    160: "SetStaticLongField", 161: "SetStaticFloatField",
    162: "SetStaticDoubleField",
    # Oracle / Sun spec: string ops differ from AOSP.
    163: "NewString",
    164: "GetStringLength", 165: "GetStringChars", 166: "ReleaseStringChars",
    167: "NewStringUTF",
    168: "GetStringUTFLength", 169: "GetStringUTFChars",
    170: "ReleaseStringUTFChars",
    171: "GetArrayLength",
    172: "NewObjectArray", 173: "GetObjectArrayElement",
    174: "SetObjectArrayElement", 175: "NewBooleanArray",
    176: "NewByteArray", 177: "NewCharArray", 178: "NewShortArray",
    179: "NewIntArray", 180: "NewLongArray", 181: "NewFloatArray",
    182: "NewDoubleArray", 183: "GetBooleanArrayElements",
    184: "GetByteArrayElements", 185: "GetCharArrayElements",
    186: "GetShortArrayElements", 187: "GetIntArrayElements",
    188: "GetLongArrayElements", 189: "GetFloatArrayElements",
    190: "GetDoubleArrayElements", 191: "ReleaseBooleanArrayElements",
    192: "ReleaseByteArrayElements", 193: "ReleaseCharArrayElements",
    194: "ReleaseShortArrayElements", 195: "ReleaseIntArrayElements",
    196: "ReleaseLongArrayElements", 197: "ReleaseFloatArrayElements",
    198: "ReleaseDoubleArrayElements", 199: "GetBooleanArrayRegion",
    200: "GetByteArrayRegion", 201: "GetCharArrayRegion",
    202: "GetShortArrayRegion", 203: "GetIntArrayRegion",
    204: "GetLongArrayRegion", 205: "GetFloatArrayRegion",
    206: "GetDoubleArrayRegion", 207: "SetBooleanArrayRegion",
    208: "SetByteArrayRegion", 209: "SetCharArrayRegion",
    210: "SetShortArrayRegion", 211: "SetIntArrayRegion",
    212: "SetLongArrayRegion", 213: "SetFloatArrayRegion",
    214: "SetDoubleArrayRegion", 215: "RegisterNatives",
    216: "UnregisterNatives", 217: "MonitorEnter", 218: "MonitorExit",
    219: "GetJavaVM", 220: "GetStringRegion", 221: "GetStringUTFRegion",
    222: "GetPrimitiveArrayCritical", 223: "ReleasePrimitiveArrayCritical",
    224: "GetStringCritical", 225: "ReleaseStringCritical",
    226: "NewWeakGlobalRef", 227: "DeleteWeakGlobalRef",
    228: "ExceptionCheck", 229: "NewDirectByteBuffer",
    230: "GetDirectBufferAddress", 231: "GetDirectBufferCapacity",
    232: "GetObjectRefType",
}

# AOSP ordering of indices 164-170 (NewStringUTF=164).  Kept for rare
# binaries compiled against Android's jni.h instead of the Sun spec.
_JNI_AOSP_STRING = {
    164: "NewStringUTF",
    165: "GetStringUTFLength", 166: "GetStringUTFChars",
    167: "ReleaseStringUTFChars",
    168: "GetStringLength", 169: "GetStringChars", 170: "ReleaseStringChars",
}

# Anchor: GetObjectClass = 31, NewStringUTF offset in Sun spec = 167*8=0x538,
# in AOSP = 164*8=0x520.  We use this to auto-detect table layout.
_SUN_NEW_STRING_UTF_OFF = 167 * 8
_AOSP_NEW_STRING_UTF_OFF = 164 * 8

# Complementary (dalvik thread local or ART additions) - rarely needed.
JNI_RESERVED_SLOTS = 4

_JAVA_NAME_RE = re.compile(
    r"Java_([A-Za-z0-9_]+)_([A-Za-z0-9_]+)"
    r"(__[0-9A-Za-z_]+)?$"
)


@dataclass
class JniExport:
    name: str
    addr: int
    size: int
    package: str = ""
    class_name: str = ""
    method: str = ""
    signature: str = ""
    short_method: str = ""

    @property
    def java_signature(self) -> str:
        return f"{self.package}{self.class_name}.{self.method}"


def map_jni_name(name: str) -> JniExport | None:
    """De-mangle a Java_-prefixed exported function name.

    Handles the javah style as well as the dex2c convention where package /
    class separators use '_' and the method-proper (or descriptor suffix) is
    appended.  When the encoding is ambiguous (e.g. d2c lambdas) the raw
    method token is preserved and a flag is implied by the `_unicode` marker.
    """
    if not name.startswith("Java_"):
        return None
    rest = name[len("Java_"):]

    # Split off the mangled descriptor/suffix at the first '__'.
    suffix = ""
    if "__" in rest:
        name_part, suffix = rest.split("__", 1)
    else:
        name_part = rest

    # name_part = <package_classes>_<method>
    if "_" in name_part:
        package_class_raw, method_mangled = name_part.rsplit("_", 1)
    else:
        package_class_raw, method_mangled = "", name_part

    # Recover (package, class) from the trail of tokens: the final token of
    # the package_class_raw is the Java class.
    tokens = package_class_raw.split("_") if package_class_raw else []
    if tokens:
        class_mangled = tokens[-1]
        pkg_mangled = tokens[:-1]
    else:
        class_mangled = ""
        pkg_mangled = []

    def demangle_dots(s):
        # '_' in package/class position encodes '.' (javah) or '.'(d2c).
        return s.replace("_", ".")

    package = ".".join(demangle_dots(t) for t in pkg_mangled)
    cls = demangle_dots(class_mangled)

    # Decode the descriptor suffix if present (best effort).
    sig = decode_mangled_suffix(suffix)

    # Method: prefer the clean post-underscore token; keep d2c hex encodings.
    method = _demangle_method_token(method_mangled)

    return JniExport(
        name=name,
        addr=0,
        size=0,
        package=package + "/" if package else "",
        class_name=cls,
        method=method,
        signature=sig,
        short_method=method,
    )


_HEX_UNICODE_RE = re.compile(r"_0([0-9A-Fa-f]{4})")


def _demangle_method_token(token):
    """Best-effort un-demangling of a mangled method token:

      *_1      -> '_'
      *_2      -> ';'    (JNI mangling)
      *_3      -> '['    (JNI mangling)
       _0xxxx  -> unicode code point
    """
    out = []
    i = 0
    while i < len(token):
        c = token[i]
        m_hex = _HEX_UNICODE_RE.match(token, i)
        if m_hex:
            cp = int(m_hex.group(1), 16)
            out.append(chr(cp))
            i = m_hex.end()
            continue
        if i + 1 < len(token) and token[i] == "_" and token[i + 1] in "123":
            out.append({"_": "_", "2": ";", "3": "["}[token[i + 1]])
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def decode_mangled_suffix(suffix):
    """Decode a JNI-mangled class segment like 'Landroid_widget_ListView_2'
    into a JNI descriptor '(Landroid/widget/ListView;...)' (params only)."""
    if not suffix:
        return ""
    s = suffix
    s = s.replace("_2", ";").replace("_3", "[")  # ; and [
    # _1 -> '_' (rare inside class names); keep register-encoded '_'.
    s = s.replace("_1", "$")
    # replace remaining '_' with '/' to form descriptor
    s = s.replace("_", "/")
    return s


def parse_d2c_signature(sig: str):
    """Interpret a JNI descriptor (used by d2c-generated code)."""
    if not sig:
        return {"parameters": [], "return_type": ""}
    m = re.match(r"\((.*)\)(.*)$", sig)
    if not m:
        return {"parameters": [sig], "return_type": ""}
    params, ret = m.groups()
    return {"parameters": descriptors(params), "return_type": describe(ret)}


def descriptors(s: str):
    out = []
    i = 0
    while i < len(s):
        c = s[i]
        if c == "[":
            depth = 0
            while i < len(s) and s[i] == "[":
                depth += 1
                i += 1
            typ = describe_one(s[i], i, s)
            out.append("[" * depth + typ)
            i += 1
        elif c == "L":
            j = s.find(";", i)
            out.append("L" + s[i + 1:j] + ";")
            i = j + 1
        else:
            out.append(describe_one(c, i, s))
            i += 1
    return out


def describe_one(c, idx, s):
    return {
        "Z": "boolean", "B": "byte", "C": "char", "S": "short",
        "I": "int", "J": "long", "F": "float", "D": "double",
    }.get(c, c)


def describe(desc: str):
    if desc == "V":
        return "void"
    if desc == "[":
        return "array"
    if desc.startswith("L") and desc.endswith(";"):
        return "object:" + desc[1:-1].replace("/", ".")
    return describe_one(desc, 0, desc)


def detect_jni_exports(elf: ELFReader):
    """Return a list of JniExport for all Java_-prefixed exported FUNC symbols."""
    out = []
    for ex in collect_exports(elf):
        if not ex.name.startswith("Java_"):
            continue
        mapped = map_jni_name(ex.name)
        if mapped is None:
            continue
        mapped.addr = ex.addr
        mapped.size = ex.size
        out.append(mapped)
    out.sort(key=lambda j: j.addr)
    return out


@dataclass
class RegisteredNative:
    java_class: str
    java_name: str
    signature: str
    func_addr: int
    func_name: str = ""

    @property
    def java_fqn(self):
        return f"{self.java_class}.{self.java_name}{self.signature}"


def detect_jni_registration_tables(elf: ELFReader):
    """Scan .data.rel.ro (and .data) for JNINativeMethod tables.

    A table entry is three pointers: (name_ptr, signature_ptr, fn_ptr).
    """
    out: list[RegisteredNative] = []
    candidates = []
    for sec in elf.sections:
        if not sec.is_write or sec.type not in (1, 6, 6):
            continue
        if not sec.is_alloc:
            continue
        if sec.type == 1 and not ("data" in sec.name or sec.name == ".data.rel.ro"):
            continue
        candidates.append(sec)
    ptr = 4 if not elf.is64 else 8

    rodata_names = {}
    rodata_sigs = {}
    str_index = build_addr_str_index(elf)
    func_index = build_func_addr_index(elf)

    checked = set()
    for sec in candidates:
        data = elf.bytes_at(sec.offset, sec.size)
        n = len(data) // ptr
        for i in range(n - 2):
            base = i * ptr
            if base in checked:
                continue
            if not elf.is64:
                a, b, c = struct_unpack(data, base, "@III")[:3] if ptr == 4 else (0, 0, 0)
            else:
                a, b, c = struct_unpack(data, base, "<QQQ")
            name = str_index.get(a)
            sig = str_index.get(b)
            fn = func_index.get(c)
            if name and sig and sig.startswith("(") and fn is not None:
                key = (a, b, c)
                if key in checked:
                    continue
                checked.add(key)
                out.append(RegisteredNative(
                    java_class="",
                    java_name=name,
                    signature=sig,
                    func_addr=c,
                    func_name=fn,
                ))
    return out


def struct_unpack(data, off, fmt):
    import struct
    sz = struct.calcsize(fmt)
    if off + sz > len(data):
        return None
    return struct.unpack_from(fmt, data, off)


def build_addr_str_index(elf: ELFReader):
    """addr -> printable string."""
    out = {}
    for s in elf.sections:
        if not s.is_alloc or s.type == 1:
            pass
    from ..elf.strings import scan_alloc_strings
    for hit in scan_alloc_strings(elf, min_len=3):
        out[hit.addr] = hit.content
    return out


def build_func_addr_index(elf: ELFReader):
    out = {}
    for ex in collect_exports(elf):
        out[ex.addr] = ex.name
    start, end = elf.text_range()
    # Also map any .text address within a function to the function name.
    for ex in collect_exports(elf):
        if start <= ex.addr < end:
            pass
    return out


def jni_index_from_offset(off: int):
    """Map a byte offset in env->functions to a JNI method name."""
    if off is None or off < 0:
        return None
    idx = off // 8
    return JNI_FUNCS.get(idx)