"""Bounds-checked parsing of ordinary PE Import Directory symbol names.

Returns None for malformed/unsupported layouts (legacy detection can remain
a fallback), and a possibly empty set for well-formed PE imports. Never maps
the file into memory as executable code or loads any DLL.
"""
from __future__ import annotations

import struct


def _read(data: bytes, fmt: str, offset: int):
    if offset < 0 or offset + struct.calcsize(fmt) > len(data):
        return None
    try:
        return struct.unpack_from(fmt, data, offset)
    except (ValueError, struct.error):
        return None

_Section = tuple[int, int, int, int]


def _optional_header(data: bytes) -> tuple[int, int, int, bool] | None:
    """Return (nsects, optsize, opt offset, is_64) for a plausible PE header."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    start = _read(data, "<I", 0x3C)
    if start is None:
        return None
    pe = start[0]
    if pe < 0x40 or pe + 24 > len(data) or data[pe:pe + 4] != b"PE\0\0":
        return None
    sections = _read(data, "<H", pe + 6)
    optional_size = _read(data, "<H", pe + 20)
    if sections is None or optional_size is None:
        return None
    nsects, optsize = sections[0], optional_size[0]
    if nsects < 1 or nsects > 96 or optsize < 96:
        return None
    opt = pe + 24
    if opt + optsize > len(data):
        return None
    magic = _read(data, "<H", opt)
    if magic is None or magic[0] not in {0x10B, 0x20B}:
        return None
    return nsects, optsize, opt, magic[0] == 0x20B


def _import_directory(data: bytes, opt: int, optsize: int, is_64: bool) -> tuple[int, int] | None:
    directory = opt + (112 if is_64 else 96)
    number = _read(data, "<I", opt + (108 if is_64 else 92))
    if number is None or number[0] < 2 or directory + 16 > opt + optsize:
        return None
    return _read(data, "<II", directory + 8)


def _read_sections(data: bytes, table: int, nsects: int) -> list[_Section] | None:
    if table + nsects * 40 > len(data):
        return None
    section_data: list[_Section] = []
    for i in range(nsects):
        fields = _read(data, "<IIII", table + i * 40 + 8)
        if fields is None:
            return None
        virtual_size, addr, raw_size, raw_ptr = fields
        if raw_ptr > len(data) or raw_size > len(data) - raw_ptr:
            return None
        section_data.append((addr, max(virtual_size, raw_size), raw_size, raw_ptr))
    return section_data


def _map_rva(sections: list[_Section], rva: int, n: int) -> int | None:
    for addr, extent, raw_size, raw_ptr in sections:
        if addr <= rva < addr + extent:
            delta = rva - addr
            if delta <= raw_size and n <= raw_size - delta:
                return raw_ptr + delta
    return None


def _symbol_name(data: bytes, sections: list[_Section], name_rva: int) -> str | None:
    hint = _map_rva(sections, name_rva, 3)
    if hint is None:
        return None
    end = data.find(b"\0", hint + 2, min(hint + 258, len(data)))
    if end < 0:
        return None
    try:
        symbol = data[hint + 2:end].decode("ascii")
    except UnicodeDecodeError:
        return None
    return symbol or None


def _read_thunks(
    data: bytes, sections: list[_Section], thunk_rva: int, is_64: bool, names: set[str]
) -> bool:
    """Collect named imports of one DLL; False when the table is malformed."""
    entry_size = 8 if is_64 else 4
    entry_fmt = "<Q" if is_64 else "<I"
    high_bit = 1 << (63 if is_64 else 31)
    for j in range(4096):
        pos = _map_rva(sections, thunk_rva + j * entry_size, entry_size)
        if pos is None:
            return False
        entry = _read(data, entry_fmt, pos)
        if entry is None:
            return False
        value = entry[0]
        if value == 0:
            return True
        if value & high_bit:
            continue  # ordinal imports are not named symbols
        symbol = _symbol_name(data, sections, value & (high_bit - 1))
        if symbol is None:
            return False
        names.add(symbol)
    return False


def _read_descriptor(
    data: bytes, sections: list[_Section], import_rva: int, index: int, is_64: bool, names: set[str]
) -> bool | None:
    """Parse one import descriptor: True when it is the terminator, None on error."""
    desc_pos = _map_rva(sections, import_rva + index * 20, 20)
    if desc_pos is None:
        return None
    descriptor = _read(data, "<IIIII", desc_pos)
    if descriptor is None:
        return None
    original_thunk, _, _, dll_rva, first_thunk = descriptor
    if descriptor == (0, 0, 0, 0, 0):
        return True
    if not dll_rva or not first_thunk:
        return None
    dll_pos = _map_rva(sections, dll_rva, 1)
    if dll_pos is None or data.find(b"\0", dll_pos, min(dll_pos + 257, len(data))) < 0:
        return None
    if not _read_thunks(data, sections, original_thunk or first_thunk, is_64, names):
        return None
    return False


def pe_imported_symbols(data: bytes) -> set[str] | None:
    """Read named imports from a PE32 or PE32+ binary, without execution."""
    header = _optional_header(data)
    if header is None:
        return None
    nsects, optsize, opt, is_64 = header
    import_dir = _import_directory(data, opt, optsize, is_64)
    if import_dir is None:
        return None
    import_rva, import_size = import_dir
    sections = _read_sections(data, opt + optsize, nsects)
    if sections is None:
        return None
    if not import_rva:
        return set()
    if import_size < 40 or import_size > 65536:
        return None
    names: set[str] = set()
    for i in range(min(import_size // 20, 1024)):
        done = _read_descriptor(data, sections, import_rva, i, is_64, names)
        if done is None:
            return None
        if done:
            return names
    return None
