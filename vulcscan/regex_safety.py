"""Decide which sinks an allowlist regular expression protects.

A guard such as ``re.fullmatch(r"[a-z0-9_-]+", name)`` restricts ``name`` to a
known character set. This module computes that set for a small, deterministic
subset of regex syntax and reports the sink categories it makes safe. Patterns
outside the subset (dot, negated classes, lookarounds, backreferences, unknown
escapes) protect nothing.
"""

from __future__ import annotations

import string

from .dataflow import CODE, COMMAND, FILESYSTEM, SQL, TEMPLATE

_DIGITS = set(string.digits)
_WORD = set(string.ascii_letters + string.digits + "_")
_ESCAPE_CLASSES = {"d": _DIGITS, "w": _WORD}

# Characters that keep each sink category exploitable.
_DANGEROUS = {
    COMMAND: set(" \t\n\r;&|$`<>()[]{}*?!#~'\"\\") | {"\x00"},
    SQL: set("'\"`;\\\n\r") | {"-", " ", "\t", "\x00", "/", "*"},
    CODE: set("()[]{}.;'\"`\\\n\r+-*/%=<>!&|^~@:, \t"),
    FILESYSTEM: set("/\\.:\x00\n\r") | {"~"},
    TEMPLATE: set("{}%#$<>`'\"\\"),
}


def safe_for(pattern: str, fullmatch: bool) -> frozenset[str]:
    """Return the sink categories that ``pattern`` makes safe, or an empty set."""
    body = pattern
    if body.startswith("^"):
        body = body[1:]
    elif body.startswith(r"\A"):
        body = body[2:]
    if body.endswith(r"\Z"):
        body = body[:-2]
    elif body.endswith(r"\z"):
        body = body[:-2]
    elif fullmatch and body.endswith("$") and not body.endswith(r"\$"):
        body = body[:-1]
    elif not fullmatch:
        return frozenset()  # re.match without \Z leaves the tail unchecked; '$' accepts a trailing newline
    allowed = _allowed_characters(body)
    if allowed is None or not allowed:
        return frozenset()
    return frozenset(category for category, dangerous in _DANGEROUS.items() if not allowed & dangerous)


def _allowed_characters(body: str) -> set[str] | None:
    allowed: set[str] = set()
    index = 0
    while index < len(body):
        char = body[index]
        if char == "[":
            end, chars = _character_class(body, index)
            if chars is None:
                return None
            allowed |= chars
            index = end
            continue
        if char == "\\":
            if index + 1 >= len(body):
                return None
            escaped = body[index + 1]
            if escaped in _ESCAPE_CLASSES:
                allowed |= _ESCAPE_CLASSES[escaped]
            elif not escaped.isalnum():
                allowed.add(escaped)
            else:
                return None
            index += 2
            continue
        if char in "+*?":
            index += 1
            continue
        if char == "{":
            end = body.find("}", index)
            if end < 0 or not all(part.isdigit() or part == "" for part in body[index + 1 : end].split(",")):
                return None
            index = end + 1
            continue
        if char in ".()|^$":
            return None
        allowed.add(char)
        index += 1
    return allowed


def _character_class(body: str, start: int) -> tuple[int, set[str] | None]:
    index = start + 1
    if index < len(body) and body[index] == "^":
        return start, None
    chars: set[str] = set()
    first = True
    while index < len(body):
        char = body[index]
        if char == "]" and not first:
            return index + 1, chars
        first = False
        if char == "\\":
            if index + 1 >= len(body):
                return start, None
            escaped = body[index + 1]
            if escaped in _ESCAPE_CLASSES:
                chars |= _ESCAPE_CLASSES[escaped]
            elif not escaped.isalnum():
                chars.add(escaped)
            else:
                return start, None
            index += 2
            continue
        if index + 2 < len(body) and body[index + 1] == "-" and body[index + 2] != "]":
            low, high = char, body[index + 2]
            if ord(low) > ord(high) or ord(high) - ord(low) > 128:
                return start, None
            chars |= {chr(code) for code in range(ord(low), ord(high) + 1)}
            index += 3
            continue
        chars.add(char)
        index += 1
    return start, None
