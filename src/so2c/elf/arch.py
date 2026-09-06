"""Architecture / Android ABI detection and mapping."""

from __future__ import annotations

from .reader import EM_X86, EM_X86_64, EM_ARM, EM_AARCH64, ELFReader


class ArchInfo:
    __slots__ = ("elf_machine", "elf_name", "abi", "abi_list", "word_size", "endian",
                 "cs_arch", "cs_mode", "reg_bits", "pointer_size", "jni_arg_regs")

    def __init__(self, elf_machine, elf_name, abi, word_size, endian, cs_arch, cs_mode,
                 reg_bits, pointer_size, jni_arg_regs):
        self.elf_machine = elf_machine
        self.elf_name = elf_name
        self.abi = abi
        self.abi_list = abi.split("/")
        self.word_size = word_size
        self.endian = endian
        self.cs_arch = cs_arch
        self.cs_mode = cs_mode
        self.reg_bits = reg_bits
        self.pointer_size = pointer_size
        self.jni_arg_regs = jni_arg_regs

    def __repr__(self):
        return (f"<ArchInfo {self.abi} ({self.elf_name}) "
                f"{self.word_size}-bit {self.endian}>")


# Capstone constants may not exist if capstone isn't installed; guard them.
def _cs(arch, mode):
    try:
        import capstone  # noqa: F401
    except Exception:
        return None
    return arch, mode


ARM64_CS = _cs(183, 0)      # capstone.CS_ARCH_ARM64 / CS_MODE_LITTLE_ENDIAN
ARM_CS = _cs(40, 0)         # capstone.CS_ARCH_ARM / CS_MODE_ARM
X86_32_CS = _cs(3, 0)       # capstone.CS_ARCH_X86 / CS_MODE_32
X86_64_CS = _cs(62, 0)      # capstone.CS_ARCH_X86 / CS_MODE_64

_ARCH_MAP = {
    EM_AARCH64: ArchInfo(
        EM_AARCH64, "aarch64", "arm64-v8a", 64, "little",
        ARM64_CS, None, 64, 8, ("x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"),
    ),
    EM_ARM: ArchInfo(
        EM_ARM, "arm", "armeabi-v7a", 32, "little",
        ARM_CS, None, 32, 4, ("r0", "r1", "r2", "r3"),
    ),
    EM_X86_64: ArchInfo(
        EM_X86_64, "x86_64", "x86_64", 64, "little",
        X86_64_CS, None, 64, 8, ("rdi", "rsi", "rdx", "rcx", "r8", "r9"),
    ),
    EM_X86: ArchInfo(
        EM_X86, "x86", "x86", 32, "little",
        X86_32_CS, None, 32, 4, ("ecx", "edx"),  # esi: (env, thiz, ...)
    ),
}

ABI_TO_ANDROID_NDK = {
    "arm64-v8a": "arm64-v8a",
    "armeabi-v7a": "armeabi-v7a",
    "x86_64": "x86_64",
    "x86": "x86",
}

# Big / little endian suffix used in capstone mode values.
ENDIAN_BIG = 0x80000000


def detect_arch(elf: ELFReader) -> ArchInfo:
    info = _ARCH_MAP.get(elf.machine)
    if info is None:
        raise ValueError(f"unsupported ELF machine {elf.machine}")
    return info


def cs_config(info: ArchInfo):
    """Return a (cs_arch, cs_mode) tuple usable with capstone.Cs(),
    or None (capstone unavailable)."""
    if info is None or info.cs_arch is None:
        return None
    arch, _ = info.cs_arch
    try:
        import capstone
        if arch == 183:  # ARM64
            return (capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
        if arch == 40:  # ARM
            return (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
        if arch == 3:   # X86
            return (capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        if arch == 62:  # X86_64
            return (capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    except Exception:
        return None
    return None


def jni_calling_convention(info: ArchInfo):
    """Nominal JNI register assignment for the first three args."""
    regs = info.jni_arg_regs
    if info.elf_machine == EM_X86:
        # x86 (32-bit): args on stack; symbolic names are hard.
        return ("env", "thiz", None)
    if len(regs) >= 3:
        return (regs[0], regs[1], regs[2])
    return ("?", "?", "?")