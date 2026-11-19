from __future__ import annotations

import struct

from vulcscan.binary import analyze_binary
from vulcscan.elf_dynamic import elf_dynamic_issues


def _elf(*, bits: int = 64, relro: bool = True, now: bool = True,
         rpath: str | None = None, runpath: str | None = None) -> bytes:
    big = bits == 64
    base = 0x400000 if big else 0x8048000
    size = 0x600
    data = bytearray(size)
    data[0:4] = b"\x7fELF"
    data[4], data[5], data[6] = (2 if big else 1), 1, 1
    struct.pack_into("<H", data, 16, 3)  # ET_DYN
    phoff, phsize = (64, 56) if big else (52, 32)
    struct.pack_into("<Q" if big else "<I", data, 32 if big else 28, phoff)
    struct.pack_into("<HH", data, 54 if big else 42, phsize, 3 if relro else 2)
    strings = (runpath if runpath is not None else rpath if rpath is not None else "lib") + "\0"
    data[0x300:0x300 + len(strings)] = strings.encode()
    entries = [(5, base + 0x300), (10, 0x100)]
    if rpath is not None:
        entries.append((15, 0))
    if runpath is not None:
        entries.append((29, 0))
    if now:
        entries.append((24, 0))
    entries.append((0, 0))
    entfmt = "<qQ" if big else "<iI"
    stride = struct.calcsize(entfmt)
    for i, entry in enumerate(entries):
        struct.pack_into(entfmt, data, 0x200 + i * stride, *entry)

    def header(i: int, typ: int, offset: int, vaddr: int, filesz: int):
        if big:
            struct.pack_into("<IIQQQQQQ", data, phoff + i * phsize,
                             typ, 4, offset, vaddr, 0, filesz, filesz, 0x1000)
        else:
            struct.pack_into("<IIIIIIII", data, phoff + i * phsize,
                             typ, offset, vaddr, 0, filesz, filesz, 4, 0x1000)

    header(0, 1, 0, base, size)
    header(1, 2, 0x200, base + 0x200, len(entries) * stride)
    if relro:
        header(2, 0x6474E552, 0x200, base + 0x200, 0x100)
    return bytes(data)


def test_full_relro_does_not_emit_dynamic_hardening_issue() -> None:
    issues = elf_dynamic_issues(_elf())
    assert not issues


def test_partial_and_missing_relro_are_distinguished() -> None:
    partial = elf_dynamic_issues(_elf(now=False))
    absent = elf_dynamic_issues(_elf(relro=False))
    assert len(partial) == 1 and "partial RELRO" in partial[0]
    assert len(absent) == 1 and "RELRO absent" in absent[0]


def test_elf32_dynamic_relro_and_rpath() -> None:
    issues = elf_dynamic_issues(_elf(bits=32, relro=True, now=False, rpath="../plugins"))
    assert len(issues) == 2
    assert "partial RELRO" in issues[0]
    assert "RPATH" in issues[1]


def test_runpath_relative_or_temp_is_reported() -> None:
    for path in ("./plugins", ":", "/tmp/libs"):
        issues = elf_dynamic_issues(_elf(runpath=path))
        assert len(issues) == 1
        assert "RUNPATH" in issues[0]


def test_origin_relative_and_absolute_system_paths_are_not_flagged() -> None:
    for path in ("$ORIGIN/lib", "/usr/lib", "/opt/app/lib"):
        issues = elf_dynamic_issues(_elf(runpath=path))
        assert not issues


def test_malformed_and_truncated_elf_does_not_crash() -> None:
    data = bytearray(_elf())
    data[54:58] = b"\x00\x00\xff\xff"  # malformed size and count
    for value in (b"\x7fELF", bytes(data), _elf()[:100]):
        assert elf_dynamic_issues(value) == []


def test_dynamic_checks_are_integrated_into_binary_findings() -> None:
    found = analyze_binary("service.elf", _elf(now=False, runpath="./plugins"))
    hardening = [f for f in found if f.rule_id == "BINARY-HARDENING-001"]
    assert any("partial RELRO" in f.evidence for f in hardening)
    assert any("RUNPATH" in f.evidence for f in hardening)
