

def _program_header_table(data: bytes, big: bool, e: str) -> tuple[int, int, int] | None:
    """Return (phoff, entry size, count) for a plausible executable or shared object."""
    minimum = 64 if big else 52
    if len(data) < minimum:
        return None
    kind = _unpack(e + "H", data, 16)
    off = _unpack(e + ("Q" if big else "I"), data, 32 if big else 28)
    sizes = _unpack(e + "HH", data, 54 if big else 42)
    if kind is None or kind[0] not in (2, 3) or off is None or sizes is None:
        return None
    phoff, (step, count) = off[0], sizes
    if step < (56 if big else 32) or not 0 < count <= 4096:
        return None
    if phoff < minimum or phoff + count * step > len(data):
        return None
    return phoff, step, count


def _program_headers(
    data: bytes, big: bool, e: str, table: tuple[int, int, int]
) -> tuple[bool, list[tuple[int, int, int]], tuple[int, int]] | None:
    """Return (has RELRO, PT_LOAD segments, PT_DYNAMIC extent), or None when unusable."""
    phoff, step, count = table
    fmt = e + ("IIQQQQQQ" if big else "IIIIIIII")
    segments: list[tuple[int, int, int]] = []
    relro = False
    dynamic = None
    for i in range(count):
        ph = _unpack(fmt, data, phoff + i * step)
        if ph is None:
            return None
        if big:
            typ, _, file_offset, addr, _, size, _, _ = ph
        else:
            typ, file_offset, addr, _, size, _, _, _ = ph
        if typ == 0x6474E552:
            relro = True
        elif typ == 1:
            segments.append((file_offset, addr, size))
        elif typ == 2:
            if dynamic is not None:
                return None
            dynamic = (file_offset, size)
    if dynamic is None:
        return None
    return relro, segments, dynamic


def _dynamic_entries(data: bytes, big: bool, e: str, dynamic: tuple[int, int]) -> dict[int, int] | None:
    dynoff, dynsize = dynamic
    entry_size = 16 if big else 8
    if dynsize < entry_size or dynoff > len(data) or dynsize > len(data) - dynoff:
        return None
    dynfmt = e + ("qQ" if big else "iI")
    entries: dict[int, int] = {}
    for i in range(min(dynsize // entry_size, 4096)):
        pair = _unpack(dynfmt, data, dynoff + i * entry_size)
        if pair is None:
            return None
        tag, val = pair
        if tag == 0:
            return entries
        entries[tag] = val
    return None


def _string_table(
    data: bytes, segments: list[tuple[int, int, int]], entries: dict[int, int]
) -> tuple[int, int] | None:
    """Locate DT_STRTAB in the file; return (file position, size)."""
    straddr, size = entries.get(5), entries.get(10)
    if straddr is None or size is None or size <= 0:
        return None
    pos = None
    for fileoff, addr, filesz in segments:
        if addr <= straddr < addr + filesz and size <= filesz - (straddr - addr):
            pos = fileoff + straddr - addr
            break
    if pos is None or pos > len(data) or size > len(data) - pos:
        return None
    return pos, size


def _search_path_issues(data: bytes, entries: dict[int, int], pos: int, size: int) -> list[str]:
    issues = []
    for tag, label in ((15, "RPATH"), (29, "RUNPATH")):
        if tag not in entries or entries[tag] >= size:
            continue
        start = pos + entries[tag]
        end = data.find(b"\x00", start, pos + size)
        if end < 0:
            continue
        raw = data[start:end].decode("utf-8", errors="replace")
        if any(_unsafe_library_search_entry(entry) for entry in raw.split(":")):
            issues.append(f"ELF {label} contains empty, relative or temporary-library lookup entries (untrusted path risk).")
    return issues


def elf_dynamic_issues(data: bytes) -> list[str]:
    if len(data) < 52 or not data.startswith(b"\x7fELF"):
        return []
    bits, endian_flag = data[4], data[5]
    if bits not in {1, 2} or endian_flag not in {1, 2}:
        return []
    big = bits == 2
    e = "<" if endian_flag == 1 else ">"
    table = _program_header_table(data, big, e)
    if table is None:
        return []
    headers = _program_headers(data, big, e, table)
    if headers is None:
        return []
    relro, segments, dynamic = headers
    entries = _dynamic_entries(data, big, e, dynamic)
    if entries is None:
        return []
    now = 24 in entries or bool(entries.get(30, 0) & 8) or bool(entries.get(0x6FFFFFFB, 0) & 1)
    issues = []
    if not relro:
        issues.append("ELF dynamic binary has no GNU_RELRO program header (RELRO absent).")
    elif not now:
        issues.append("ELF dynamic binary has GNU_RELRO but no BIND_NOW (partial RELRO).")
    if 15 not in entries and 29 not in entries:
        return issues
    located = _string_table(data, segments, entries)
    if located is None:
        return issues
    return issues + _search_path_issues(data, entries, *located)
