"""Conservative, execution-free checks for compiled artifacts."""

from __future__ import annotations

import re
import struct
from pathlib import Path

from .models import Confidence, Finding, Location
from .rules import RULES, remediations_for

_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".so", ".dylib", ".bin", ".elf", ".o", ".obj",
    ".a", ".lib", ".class", ".jar", ".war", ".ear", ".wasm", ".pyc", ".pyd",
}
_DANGEROUS = (
    (b"gets", "gets"),
    (b"strcpy", "strcpy"),
    (b"strcat", "strcat"),
    (b"sprintf", "sprintf"),
    (b"vsprintf", "vsprintf"),
    (b"system", "system"),
    (b"popen", "popen"),
    (b"WinExec", "WinExec"),
    (b"ShellExecute", "ShellExecute"),
    (b"Runtime.exec", "Runtime.exec"),
)
_SECRET = re.compile(
    rb"(?i)(?:api[_-]?key|secret|token|password|passwd|pwd)\s*[:=]\s*[\"']?([A-Za-z0-9_./+!@#$%^&*=-]{8,})"
)


def looks_like_binary(path: Path, head: bytes) -> bool:
    suffix = path.suffix.casefold()
    return suffix in _EXTENSIONS or head.startswith(
        (b"MZ", b"\x7fELF", b"\xca\xfe\xba\xbe", b"\xfe\xed\xfa", b"\xcf\xfa\xed\xfe", b"\x00asm")
    )


def analyze_binary(relative: str, data: bytes) -> list[Finding]:
    kind = binary_kind(data)
    findings: list[Finding] = []

    def add(rule_id: str, sink: str, evidence: str, confidence: Confidence) -> None:
        definition = RULES[rule_id]
        findings.append(Finding(
            rule_id=rule_id,
            name=definition.name,
            cwe=definition.cwe,
            severity=definition.severity,
            confidence=confidence,
            category=definition.category,
            language=kind,
            location=Location(relative, 1, 1, 1),
            sink=sink,
            evidence=evidence,
            reason=definition.explanation,
            remediations=remediations_for(rule_id, evidence),
            tags=("binary", kind.casefold()),
        ))

    for needle, label in _DANGEROUS:
        if _symbol_present(data, needle):
            add("BINARY-DANGEROUS-001", label, f"Imported or embedded symbol: {label}", Confidence.MEDIUM)

    secret = _SECRET.search(data)
    if secret and secret.group(1) not in {b"password", b"changeme", b"example", b"placeholder"}:
        add("BINARY-SECRET-001", "embedded printable string", "Credential-like assignment embedded in binary (value redacted).", Confidence.MEDIUM)

    for evidence in _hardening_issues(data):
        add("BINARY-HARDENING-001", "executable header", evidence, Confidence.HIGH)
    return findings


def binary_kind(data: bytes) -> str:
    if data.startswith(b"MZ"):
        return "PE binary"
    if data.startswith(b"\x7fELF"):
        return "ELF binary"
    if data.startswith(b"\x00asm"):
        return "WebAssembly"
    if data.startswith(b"\xca\xfe\xba\xbe"):
        return "Java bytecode"
    if data[:4] in {b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"}:
        return "Mach-O binary"
    return "Binary"


def _symbol_present(data: bytes, needle: bytes) -> bool:
    return re.search(rb"(?<![A-Za-z0-9_])" + re.escape(needle) + rb"(?:@@?[A-Za-z0-9_.-]+)?(?![A-Za-z0-9_])", data) is not None


def _hardening_issues(data: bytes) -> list[str]:
    if data.startswith(b"MZ"):
        return _pe_hardening(data)
    if data.startswith(b"\x7fELF"):
        return _elf_hardening(data)
    return []


def _pe_hardening(data: bytes) -> list[str]:
    try:
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe:pe + 4] != b"PE\0\0":
            return []
        optional = pe + 24
        magic = struct.unpack_from("<H", data, optional)[0]
        if magic not in {0x10B, 0x20B}:
            return []
        flags = struct.unpack_from("<H", data, optional + 70)[0]
    except (struct.error, IndexError):
        return []
    issues = []
    if not flags & 0x0040:
        issues.append("PE header does not declare ASLR support (DYNAMIC_BASE absent).")
    if not flags & 0x0100:
        issues.append("PE header does not declare DEP/NX support (NX_COMPAT absent).")
    return issues


def _elf_hardening(data: bytes) -> list[str]:
    if len(data) < 64 or data[5] not in {1, 2} or data[4] not in {1, 2}:
        return []
    endian = "<" if data[5] == 1 else ">"
    bits = data[4]
    try:
        e_type = struct.unpack_from(endian + "H", data, 16)[0]
        if bits == 2:
            phoff = struct.unpack_from(endian + "Q", data, 32)[0]
            phentsize, phnum = struct.unpack_from(endian + "HH", data, 54)
        else:
            phoff = struct.unpack_from(endian + "I", data, 28)[0]
            phentsize, phnum = struct.unpack_from(endian + "HH", data, 42)
    except struct.error:
        return []
    issues = []
    if e_type == 2:
        issues.append("ELF executable is ET_EXEC, so position-independent executable hardening is absent.")
    for index in range(min(phnum, 4096)):
        offset = phoff + index * phentsize
        try:
            p_type = struct.unpack_from(endian + "I", data, offset)[0]
            flags_offset = offset + (4 if bits == 2 else 24)
            flags = struct.unpack_from(endian + "I", data, flags_offset)[0]
        except struct.error:
            break
        if p_type == 0x6474E551 and flags & 1:
            issues.append("ELF GNU_STACK program header is executable; NX stack protection is disabled.")
            break
    return issues
