"""Bounds-checked ELF .dynsym/.dynstr parser for undefined imported symbols.

A valid section header layout returns a possibly empty set; malformed or
unsupported layouts return None so callers can retain a conservative fallback.
Never imports, links, maps, or executes target binaries.
"""
from __future__ import annotations

import struct


def _unpack(fmt: str, data: bytes, offset: int):
    if offset < 0 or offset + struct.calcsize(fmt) > len(data):
        return None
    try:
        return struct.unpack_from(fmt, data, offset)
    except (struct.error, ValueError):
        return None


def elf_imported_symbols(data: bytes) -> set[str] | None:
    if len(data) < 52 or data[:4] != b"\x7fELF" or data[4] not in (1, 2) or data[5] not in (1, 2):
        return None
    wide = data[4] == 2
    endian = "<" if data[5] == 1 else ">"
    header_len = 64 if wide else 52
    if len(data) < header_len:
        return None
    offset = _unpack(endian + ("Q" if wide else "I"), data, 40 if wide else 32)
    sizes = _unpack(endian + "HH", data, 58 if wide else 46)
    if offset is None or sizes is None:
        return None
    section_start = offset[0]
    stride, count = sizes
    base_size = 64 if wide else 40
    if section_start < header_len or stride < base_size or not 0 < count <= 4096:
        return None
    if section_start > len(data) or count * stride > len(data) - section_start:
        return None

    fmt = endian + ("IIQQQQIIQQ" if wide else "IIIIIIIIII")
    sections = []
    for index in range(count):
        row = _unpack(fmt, data, section_start + index * stride)
        if row is None:
            return None
        kind, offset_in_file, section_size, link, entry_size = (
            (row[1], row[4], row[5], row[6], row[9])
            if wide else (row[1], row[4], row[5], row[6], row[9])
        )
        if section_size and (offset_in_file > len(data) or section_size > len(data) - offset_in_file):
            # SHT_NOBITS sections take no file space.
            if kind != 8:
                return None
        sections.append((kind, offset_in_file, section_size, link, entry_size))

    result: set[str] = set()
    symfmt = endian + ("IBBHQQ" if wide else "IIIBBH")
    sym_size = struct.calcsize(symfmt)
    for kind, symoffset, symsize, strindex, step in sections:
        if kind != 11:  # SHT_DYNSYM
            continue
        if strindex >= len(sections) or step < sym_size or symsize % step:
            return None
        str_kind, stroffset, strsize, _, _ = sections[strindex]
        if str_kind != 3 or strsize == 0 or symsize // step > 100000:
            return None
        for index in range(symsize // step):
            row = _unpack(symfmt, data, symoffset + index * step)
            if row is None:
                return None
            # ELF64: st_name, st_info, st_other, st_shndx, st_value, st_size
            # ELF32: st_name, st_value, st_size, st_info, st_other, st_shndx
            name_index = row[0]
            undefined = row[3] == 0 if wide else row[5] == 0
            if not undefined or not name_index:
                continue
            if name_index >= strsize:
                return None
            absolute = stroffset + name_index
            end = data.find(b"\x00", absolute, stroffset + strsize)
            if end < 0 or end - absolute > 1024:
                return None
            try:
                name = data[absolute:end].decode("ascii")
            except UnicodeDecodeError:
                return None
            if name:
                result.add(name.split("@", 1)[0])
    return result
