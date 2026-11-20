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
    if body.endswith((r"\Z", r"\z")):
        body = body[:-2]
    elif fullmatch and body.endswith("$") and not body.endswith(r"\$"):
        body = body[:-1]
    elif not fullmatch:
        return frozenset()  # re.match without \Z leaves the tail unchecked; '$' accepts a trailing newline
    allowed = _allowed_characters(body)
    if allowed is None or not allowed:
        return frozenset()
    return frozenset(category for category, dangerous in _DANGEROUS.items() if not allowed & dangerous)


def _escape_chars(body: str, index: int) -> set[str] | None:
    """Characters matched by the backslash escape at ``index``; None when unsupported."""
    if index + 1 >= len(body):
        return None
    escaped = body[index + 1]
    if escaped in _ESCAPE_CLASSES:
        return set(_ESCAPE_CLASSES[escaped])
    if not escaped.isalnum():
        return {escaped}
    return None


def _brace_quantifier_end(body: str, index: int) -> int | None:
    end = body.find("}", index)
    if end < 0 or not all(part.isdigit() or part == "" for part in body[index + 1 : end].split(",")):
        return None
    return end + 1


def _expand_range(low: str, high: str) -> set[str] | None:
    if ord(low) > ord(high) or ord(high) - ord(low) > 128:
        return None
    return {chr(code) for code in range(ord(low), ord(high) + 1)}


def _allowed_step(body: str, index: int, allowed: set[str]) -> int | None:
    """Consume one token at ``index``; return the next index, or None when unsupported."""
    char = body[index]
    if char == "[":
        end, chars = _character_class(body, index)
        if chars is None:
            return None
        allowed |= chars
        return end
    if char == "\\":
        escaped_chars = _escape_chars(body, index)
        if escaped_chars is None:
            return None
        allowed |= escaped_chars
        return index + 2
    if char in "+*?":
        return index + 1
    if char == "{":
        return _brace_quantifier_end(body, index)
    if char in ".()|^$":
        return None
    allowed.add(char)
    return index + 1


def _allowed_characters(body: str) -> set[str] | None:
    allowed: set[str] = set()
    index = 0
    while index < len(body):
        following = _allowed_step(body, index, allowed)
        if following is None:
            return None
        index = following
    return allowed


def _class_member(body: str, index: int, chars: set[str]) -> int | None:
    """Consume one character-class member; return the next index, or None when unsupported."""
    char = body[index]
    if char == "\\":
        escaped_chars = _escape_chars(body, index)
        if escaped_chars is None:
            return None
        chars |= escaped_chars
        return index + 2
    if index + 2 < len(body) and body[index + 1] == "-" and body[index + 2] != "]":
        span = _expand_range(char, body[index + 2])
        if span is None:
            return None
        chars |= span
        return index + 3
    chars.add(char)
    return index + 1


def _character_class(body: str, start: int) -> tuple[int, set[str] | None]:
    index = start + 1
    if index < len(body) and body[index] == "^":
        return start, None
    chars: set[str] = set()
    first = True
    while index < len(body):
        if body[index] == "]" and not first:
            return index + 1, chars
        first = False
        following = _class_member(body, index, chars)
        if following is None:
            return start, None
        index = following
    return start, None
