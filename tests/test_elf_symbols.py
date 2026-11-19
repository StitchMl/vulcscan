from __future__ import annotations

import struct

from vulcscan.binary import analyze_binary
from vulcscan.elf_symbols import elf_imported_symbols


def _elf(bits: int = 64, *, imported: str = "strcpy", embedded: str = "gets") -> bytes:
    wide = bits == 64
    data = bytearray(0x800)
    data[:4] = b"\x7fELF"
    data[4:7] = bytes((2 if wide else 1, 1, 1))
    struct.pack_into("<H", data, 16, 3)
    head = 64 if wide else 52
    step = 64 if wide else 40
    struct.pack_into("<Q" if wide else "<I", data, 40 if wide else 32, 0x400)
    struct.pack_into("<HH", data, 58 if wide else 46, step, 3)
    strings = b"\x00" + imported.encode() + b"\x00definedSymbol\x00"
    data[0x200:0x200 + len(strings)] = strings
    rowfmt = "<IIQQQQIIQQ" if wide else "<IIIIIIIIII"
    def section(i, kind, offset, size, link=0, entsize=0):
        row = [0, kind, 0, 0, offset, size, link, 0, 1, entsize]
        struct.pack_into(rowfmt, data, 0x400 + i * step, *row)
    section(1, 3, 0x200, len(strings))
    symfmt = "<IBBHQQ" if wide else "<IIIBBH"
    symsize = struct.calcsize(symfmt)
    section(2, 11, 0x300, symsize * 3, 1, symsize)
    if wide:
        struct.pack_into(symfmt, data, 0x300 + symsize, 1, 0x12, 0, 0, 0, 0)
        struct.pack_into(symfmt, data, 0x300 + symsize * 2, len(imported) + 2, 0x12, 0, 1, 0, 0)
    else:
        struct.pack_into(symfmt, data, 0x300 + symsize, 1, 0, 0, 0x12, 0, 0)
        struct.pack_into(symfmt, data, 0x300 + symsize * 2, len(imported) + 2, 0, 0, 0x12, 0, 1)
    data[0x600:0x600 + len(embedded) + 1] = embedded.encode() + b"\0"
    return bytes(data)


def test_structural_elf64_import_does_not_confuse_embedded_or_defined_name() -> None:
    image = _elf()
    assert elf_imported_symbols(image) == {"strcpy"}
    found = [f for f in analyze_binary("app.elf", image) if f.rule_id == "BINARY-DANGEROUS-001"]
    assert [f.sink for f in found] == ["strcpy"]
    assert "Imported ELF binary symbol" in found[0].evidence


def test_structural_elf32_import() -> None:
    image = _elf(bits=32, imported="gets", embedded="strcpy")
    assert elf_imported_symbols(image) == {"gets"}
    found = [f for f in analyze_binary("app.elf", image) if f.rule_id == "BINARY-DANGEROUS-001"]
    assert [f.sink for f in found] == ["gets"]


def test_elf32_elf64_undefined_only() -> None:
    for bits in (32, 64):
        image = bytearray(_elf(bits))
        stride = 24 if bits == 64 else 16
        offset = 0x300 + stride
        struct.pack_into("<H", image, offset + (6 if bits == 64 else 14), 1)
        assert elf_imported_symbols(bytes(image)) == set()


def test_malformed_section_table_and_string_offsets_fail_closed() -> None:
    for bits in (32, 64):
        image = bytearray(_elf(bits))
        struct.pack_into("<Q" if bits == 64 else "<I", image, 40 if bits == 64 else 32, 0x10000)
        assert elf_imported_symbols(bytes(image)) is None
    assert elf_imported_symbols(b"\x7fELF") is None


def test_unavailable_elf_section_table_falls_back_to_existing_heuristic() -> None:
    image = b"\x7fELF" + b"\x00" * 128 + b"strcpy\x00"
    assert elf_imported_symbols(image) is None
    assert any(f.rule_id == "BINARY-DANGEROUS-001" for f in analyze_binary("unknown.elf", image))
