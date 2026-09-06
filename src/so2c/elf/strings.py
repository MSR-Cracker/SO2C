"""String extraction and deobfuscation."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .reader import ELFReader, SHT_NOBITS, SHT_PROGBITS


@dataclass
class StringHit:
    addr: int
    content: str
    section: str
    length: int
    ascii: bool = True
    key: int = 0

    @property
    def display(self):
        return self.content


_PRINTABLE_MIN = 4

# ASCII printable except control chars; allow common high-bit? No - keep
# printable ASCII.
def _printable(b):
    return 32 <= b < 127


def _looks_ascii(run: bytes):
    return all(_printable(b) for b in run)


def _printable_ratio(run: bytes):
    if not run:
        return 0.0
    return sum(1 for b in run if _printable(b)) / len(run)


def _decode(run: bytes):
    try:
        return run.decode("ascii")
    except Exception:
        try:
            return run.decode("utf-8", "replace")
        except Exception:
            return run.decode("latin-1")


def scan_alloc_strings(elf: ELFReader, min_len=_PRINTABLE_MIN):
    """Scan allocate-able sections for printable C strings, returning
    StringHit sorted by address."""
    out = []
    for sec in elf.sections:
        if not sec.is_alloc or sec.type == SHT_NOBITS:
            continue
        if sec.size < min_len:
            continue
        data = elf.bytes_at(sec.offset, sec.size)
        in_str = False
        start = 0
        for i in range(len(data)):
            b = data[i]
            if _printable(b) and not in_str:
                in_str = True
                start = i
            elif not _printable(b) and in_str:
                in_str = False
                if i - start >= min_len:
                    out.append(StringHit(
                        addr=sec.addr + start,
                        content=_decode(data[start:i]),
                        section=sec.name,
                        length=i - start,
                    ))
        if in_str and len(data) - start >= min_len:
            out.append(StringHit(
                addr=sec.addr + start,
                content=_decode(data[start:]),
                section=sec.name,
                length=len(data) - start,
            ))
    out.sort(key=lambda h: (h.addr))
    return out


def _is_widened(char):
    return 0x0000 <= char <= 0xFFFF


def scan_utf16_strings(elf: ELFReader, min_len=4):
    """Scan for 16-bit (wide) printable strings among alloc sections."""
    out = []
    for sec in elf.sections:
        if not sec.is_alloc or sec.type == SHT_NOBITS or sec.size < min_len * 2:
            continue
        data = elf.bytes_at(sec.offset, sec.size)
        words = struct_unpack_16(data, "little")
        in_str = False
        start = 0
        for i, w in enumerate(words):
            c = ch_if_printable(w)
            if c is not None and not in_str:
                in_str = True
                start = i
            elif c is None and in_str:
                in_str = False
                if i - start >= min_len:
                    out.append((sec.addr + start * 2, "".join(words[start:i])))
        if in_str and len(words) - start >= min_len:
            out.append((sec.addr + start * 2, "".join(words[start:])))
    return sorted(out)


def ch_if_printable(w):
    if w == 0:
        return None
    if 32 <= w < 127:
        return chr(w)
    return None


def struct_unpack_16(data, endian):
    import struct
    n = len(data) // 2
    return list(struct.unpack_from(endian + f"{n}H", data, 0)) if n else []


# --------------------------------------------------------------------------
# Deobfuscation
# --------------------------------------------------------------------------

_XOR_TRIAL_KEYS = [0xFF, 0xAA, 0x55, 0x3C, 0x6B, 0x4D, 0x7F, 0x69, 0x42]

_WORD_CHARS = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .;:()_/$&!,'-"
)


class Deobfuscator:
    """Best-effort deobfuscation of string constants.

    Strategies attempted in order:

      1. Plain-text identification (already reported by string scan).
      2. Single byte XOR against data sections.  A candidate is only
         accepted when a *maximal contiguous run* of bytes decodes to
         printable text, the decoded text is mostly word characters, and the
         raw bytes were *not* already plain (avoids false positives from
         misaligned plaintext).
      3. If a candidate decrypt routine is identified by static heuristics we
         report its presence as a hint.
    """

    def __init__(self, elf: ELFReader):
        self.elf = elf
        self.decoded: list[StringHit] = []
        self.hints: list[str] = []

    def run(self, rodata_only=True):
        elf = self.elf
        targets = [s for s in elf.sections if s.is_alloc and s.type == SHT_PROGBITS
                   and (s.name in (".rodata", ".data", ".data.rel.ro") or
                        s.name.startswith(".rodata"))]
        for sec in targets:
            data = elf.bytes_at(sec.offset, sec.size)
            self._scan_xor_key(sec, data)
        return self.decoded

    def _scan_xor_key(self, sec, data):
        if len(data) < 12:
            return
        for key in range(1, 0x100):
            if key not in (0, 0x20):
                pass
            self._scan_single_key(sec, data, key)

    def _scan_single_key(self, sec, data, key):
        i = 0
        n = len(data)
        while i < n:
            # advance to start of a decoded-printable run
            while i < n and not _printable(data[i] ^ key):
                i += 1
            start = i
            while i < n and _printable(data[i] ^ key):
                i += 1
            end = i
            run_len = end - start
            if run_len < 8:
                continue
            decoded = bytes(b ^ key for b in data[start:end])
            # Reject when the raw bytes were already printable (plaintext).
            if _printable_ratio(data[start:end]) > 0.5:
                continue
            words = [c for c in decoded if c in b"abcdefghijklmnopqrstuvwxyz"
                     or 0 <= c < 0x80 and chr(c).isalnum()]
            if not decoded:
                continue
            alnum_ratio = sum(
                1 for b in decoded if chr(b) in _WORD_CHARS) / len(decoded)
            if alnum_ratio < 0.65:
                continue
            txt = _decode(bytes(c for c in decoded if c != 0))
            if len(txt) >= 4:
                self.decoded.append(StringHit(
                    addr=sec.addr + start, content=txt, section=sec.name,
                    length=run_len, key=key,
                ))


_WORD_RE = re.compile(r"[A-Za-z]{2,}")


def _readable_score(text: str):
    words = _WORD_RE.findall(text)
    if not words:
        return 0.0
    good = sum(1 for w in words if re.fullmatch(r"[A-Za-z][A-Za-z0-9_ .]*", w))
    return good / len(words)


def identify_native_strings():
    """No-op marker: the actual JNI/d2c decryption patterns are recognized by
    jni.analyzer; kept here for documentation clarity."""
    return None