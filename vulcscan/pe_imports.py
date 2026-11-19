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


def pe_imported_symbols(data: bytes) -> set[str] | None:
    """Read named imports from a PE32 or PE32+ binary, without execution."""
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
    is_64 = magic[0] == 0x20B
    directory = opt + (112 if is_64 else 96)
    number = _read(data, "<I", opt + (108 if is_64 else 92))
    if number is None or number[0] < 2 or directory + 16 > opt + optsize:
        return None
    import_dir = _read(data, "<II", directory + 8)
    if import_dir is None:
        return None
    import_rva, import_size = import_dir
    section_data = []
    table = opt + optsize
    if table + nsects * 40 > len(data):
        return None
    for i in range(nsects):
        h = table + i * 40
        fields = _read(data, "<IIII", h + 8)
        if fields is None:
            return None
        virtual_size, addr, raw_size, raw_ptr = fields
        if raw_ptr > len(data) or raw_size > len(data) - raw_ptr:
            return None
        section_data.append((addr, max(virtual_size, raw_size), raw_size, raw_ptr))

    def mapped(rva: int, n: int) -> int | None:
        for addr, extent, raw_size, raw_ptr in section_data:
            if addr <= rva < addr + extent:
                delta = rva - addr
                if delta <= raw_size and n <= raw_size - delta:
                    return raw_ptr + delta
        return None

    if not import_rva:
        return set()
    if import_size < 40 or import_size > 65536:
        return None
    names: set[str] = set()
    terminated = False
    for i in range(min(import_size // 20, 1024)):
        desc_pos = mapped(import_rva + i * 20, 20)
        if desc_pos is None:
            return None
        descriptor = _read(data, "<IIIII", desc_pos)
        if descriptor is None:
            return None
        original_thunk, _, _, dll_rva, first_thunk = descriptor
        if descriptor == (0, 0, 0, 0, 0):
            terminated = True
            break
        if not dll_rva or not first_thunk:
            return None
        dll_pos = mapped(dll_rva, 1)
        if dll_pos is None or data.find(b"\0", dll_pos, min(dll_pos + 257, len(data))) < 0:
            return None
        thunk_rva = original_thunk or first_thunk
        entry_size = 8 if is_64 else 4
        entry_fmt = "<Q" if is_64 else "<I"
        high_bit = 1 << (63 if is_64 else 31)
        thunk_terminated = False
        for j in range(4096):
            pos = mapped(thunk_rva + j * entry_size, entry_size)
            if pos is None:
                return None
            entry = _read(data, entry_fmt, pos)
            if entry is None:
                return None
            value = entry[0]
            if value == 0:
                thunk_terminated = True
                break
            if value & high_bit:
                continue  # ordinal imports are not named symbols
            name_rva = value & (high_bit - 1)
            hint = mapped(name_rva, 3)
            if hint is None:
                return None
            end = data.find(b"\0", hint + 2, min(hint + 258, len(data)))
            if end < 0:
                return None
            try:
                symbol = data[hint + 2:end].decode("ascii")
            except UnicodeDecodeError:
                return None
            if not symbol:
                return None
            names.add(symbol)
        if not thunk_terminated:
            return None
    return names if terminated else None
