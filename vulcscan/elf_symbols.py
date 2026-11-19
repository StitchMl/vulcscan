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


def _layout(data: bytes):
    if len(data) < 52 or data[:4] != b"\x7fELF":
        return None
    if data[4] not in (1, 2) or data[5] not in (1, 2):
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
    start = offset[0]
    stride, count = sizes
    if start < header_len or stride < (64 if wide else 40) or not 0 < count <= 4096:
        return None
    if start > len(data) or count * stride > len(data) - start:
        return None
    return endian, wide, start, stride, count


def _section_headers(data: bytes, endian: str, wide: bool, start: int, stride: int, count: int):
    fmt = endian + ("IIQQQQIIQQ" if wide else "IIIIIIIIII")
    sections = []
    for index in range(count):
        row = _unpack(fmt, data, start + index * stride)
        if row is None:
            return None
        kind, offset, size, link, step = row[1], row[4], row[5], row[6], row[9]
        if kind != 8 and size and (offset > len(data) or size > len(data) - offset):
            return None
        sections.append((kind, offset, size, link, step))
    return sections


def _symbol_name(data: bytes, fmt: str, at: int, wide: bool, strings: tuple[int, int]):
    row = _unpack(fmt, data, at)
    if row is None:
        return False, None
    name_index = row[0]
    undefined = row[3] == 0 if wide else row[5] == 0
    if not undefined or not name_index:
        return True, None
    offset, size = strings
    if name_index >= size:
        return False, None
    first = offset + name_index
    last = data.find(b"\x00", first, offset + size)
    if last < 0 or last - first > 1024:
        return False, None
    try:
        name = data[first:last].decode("ascii")
    except UnicodeDecodeError:
        return False, None
    return bool(name), name.split("@", 1)[0] if name else None


def _table_symbols(data: bytes, endian: str, wide: bool, sections: list, table: tuple):
    _, offset, size, link, stride = table
    fmt = endian + ("IBBHQQ" if wide else "IIIBBH")
    item_size = struct.calcsize(fmt)
    if link >= len(sections) or stride < item_size or size % stride:
        return None
    kind, strings_offset, strings_size, _, _ = sections[link]
    if kind != 3 or not strings_size or size // stride > 100000:
        return None
    names = set()
    for index in range(size // stride):
        valid, name = _symbol_name(
            data, fmt, offset + index * stride, wide, (strings_offset, strings_size)
        )
        if not valid:
            return None
        if name:
            names.add(name)
    return names


def elf_imported_symbols(data: bytes) -> set[str] | None:
    """Return undefined ELF imports if section tables are valid."""
    layout = _layout(data)
    if layout is None:
        return None
    endian, wide, start, stride, count = layout
    sections = _section_headers(data, endian, wide, start, stride, count)
    if sections is None:
        return None
    symbols: set[str] = set()
    for section in sections:
        if section[0] != 11:
            continue
        names = _table_symbols(data, endian, wide, sections, section)
        if names is None:
            return None
        symbols.update(names)
    return symbols
