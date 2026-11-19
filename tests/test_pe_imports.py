from __future__ import annotations

import struct

from vulcscan.binary import analyze_binary
from vulcscan.pe_imports import pe_imported_symbols


def _pe(*, bits: int = 32, imported: str | None = "strcpy",
        embedded: str | None = "gets") -> bytes:
    data = bytearray(0x800)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    pe = 0x80
    data[pe:pe + 4] = b"PE\0\0"
    struct.pack_into("<H", data, pe + 6, 1)
    optsize = 0xF0 if bits == 64 else 0xE0
    struct.pack_into("<H", data, pe + 20, optsize)
    opt = pe + 24
    struct.pack_into("<H", data, opt, 0x20B if bits == 64 else 0x10B)
    struct.pack_into("<H", data, opt + 70, 0x0140)  # ASLR and NX
    struct.pack_into("<I", data, opt + (108 if bits == 64 else 92), 16)
    directory = opt + (112 if bits == 64 else 96)
    if imported:
        struct.pack_into("<II", data, directory + 8, 0x1020, 40)
    section = opt + optsize
    data[section:section + 8] = b".rdata\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x600, 0x1000, 0x600, 0x200)
    if imported:
        # IMAGE_IMPORT_DESCRIPTOR, terminated by the next zero descriptor.
        struct.pack_into("<IIIII", data, 0x220, 0x1050, 0, 0, 0x1090, 0x1070)
        fmt = "<Q" if bits == 64 else "<I"
        struct.pack_into(fmt, data, 0x250, 0x10B0)
        data[0x290:0x29B] = b"msvcrt.dll\0"
        data[0x2B0:0x2B2] = b"\x00\x00"
        name = imported.encode("ascii") + b"\x00"
        data[0x2B2:0x2B2 + len(name)] = name
    if embedded:
        name = embedded.encode("ascii") + b"\x00"
        data[0x370:0x370 + len(name)] = name
    return bytes(data)


def test_pe32_structural_imports_ignore_unimported_embedded_strings() -> None:
    data = _pe(imported="strcpy", embedded="gets")
    assert pe_imported_symbols(data) == {"strcpy"}
    found = [f for f in analyze_binary("app.exe", data) if f.rule_id == "BINARY-DANGEROUS-001"]
    assert len(found) == 1
    assert found[0].sink == "strcpy"
    assert "Imported PE symbol" in found[0].evidence


def test_pe64_named_import_parses_without_loading_dll() -> None:
    data = _pe(bits=64, imported="gets")
    assert pe_imported_symbols(data) == {"gets"}
    found = [f for f in analyze_binary("app.dll", data) if f.rule_id == "BINARY-DANGEROUS-001"]
    assert len(found) == 1
    assert found[0].sink == "gets"


def test_no_import_directory_means_embedded_string_is_not_imported() -> None:
    data = _pe(imported=None, embedded="strcpy")
    assert pe_imported_symbols(data) == set()
    assert not [f for f in analyze_binary("app.exe", data) if f.rule_id == "BINARY-DANGEROUS-001"]


def test_malformed_or_truncated_pe_returns_unavailable_without_crash() -> None:
    data = _pe()
    broken = bytearray(data)
    # Point section raw data beyond EOF.
    opt = 0x80 + 24
    sec = opt + 0xE0
    struct.pack_into("<I", broken, sec + 20, 0xFFFFFF00)
    for sample in (b"MZ", data[:170], bytes(broken)):
        assert pe_imported_symbols(sample) is None


def test_import_by_ordinal_not_mistaken_for_name() -> None:
    data = bytearray(_pe(imported="strcpy", embedded=None))
    struct.pack_into("<I", data, 0x250, 0x8000002A)
    assert pe_imported_symbols(bytes(data)) == set()
