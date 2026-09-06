"""JNI analysis package."""

from .analyzer import (
    JNI_FUNCS, JniExport, RegisteredNative, map_jni_name, detect_jni_exports,
    detect_jni_registration_tables, parse_d2c_signature, jni_index_from_offset,
)

__all__ = [
    "JNI_FUNCS", "JniExport", "RegisteredNative", "map_jni_name",
    "detect_jni_exports", "detect_jni_registration_tables",
    "parse_d2c_signature", "jni_index_from_offset",
]