"""Explicit, rule-scoped Python/JavaScript/TypeScript comment suppressions."""
from __future__ import annotations

import io
import re
import tokenize
from typing import Any

from .models import Finding
from .source import JS_STYLE, blank_comments, split_lines

_DIRECTIVE = re.compile(r"^#\s*vulcscan:ignore\s+([A-Z][A-Z0-9_-]+)\s*$", re.IGNORECASE)
_JS_DIRECTIVE = re.compile(r"^//\s*vulcscan:ignore\s+([A-Z][A-Z0-9_-]+)\s*$", re.IGNORECASE)


def _line_comment_directive(
    text: str, clean: str, index: int
) -> tuple[int, tuple[int, str] | None]:
    """Parse the // comment at ``index``; return (end of comment, directive)."""
    end = text.find("\n", index)
    end = len(text) if end < 0 else end
    match = _JS_DIRECTIVE.fullmatch(text[index:end].strip())
    if not match:
        return end, None
    line = text.count("\n", 0, index) + 1
    line_start = text.rfind("\n", 0, index) + 1
    target = line if clean[line_start:index].strip() else line + 1
    return end, (target, match.group(1).upper())


def _javascript_directives(text: str) -> set[tuple[int, str]]:
    """Find real line comments outside strings, regexes and block comments."""
    clean = blank_comments(text, JS_STYLE)
    found: set[tuple[int, str]] = set()
    index = 0
    while index < len(text):
        pair = text[index:index + 2]
        blanked = clean[index:index + 2] == "  "
        if blanked and pair == "/*":
            close = text.find("*/", index + 2)
            index = len(text) if close < 0 else close + 2
        elif blanked and pair == "//":
            index, directive = _line_comment_directive(text, clean, index)
            if directive is not None:
                found.add(directive)
        else:
            index += 1
    return found


def _python_directives(text: str) -> set[tuple[int, str]] | None:
    """Directive comments of a Python source; None when it cannot be tokenized."""
    active: set[tuple[int, str]] = set()
    lines = split_lines(text)
    try:
        for token in tokenize.generate_tokens(io.StringIO(text).readline):
            if token.type != tokenize.COMMENT:
                continue
            match = _DIRECTIVE.fullmatch(token.string.strip())
            if not match:
                continue
            row, column = token.start
            prefix = lines[row - 1][:column]
            target = row + 1 if not prefix.strip() else row
            active.add((target, match.group(1).upper()))
    except (tokenize.TokenError, SyntaxError):
        return None
    return active


def suppression_index(files: list[Any]) -> dict[str, set[tuple[int, str]]]:
    """Recognize directive comments only (not string literals).

    An inline comment suppresses its own line. A comment-only directive
    suppresses the next physical line, never an entire function or file.
    """
    indexed: dict[str, set[tuple[int, str]]] = {}
    for source in files:
        active: set[tuple[int, str]] | None
        if source.language == "Python":
            active = _python_directives(source.text)
        elif source.language in {"JavaScript", "TypeScript"}:
            active = _javascript_directives(source.text)
        else:
            continue
        if active:
            indexed[source.relative] = active
    return indexed


def is_suppressed(finding: Finding, index: dict[str, set[tuple[int, str]]]) -> bool:
    location = finding.location
    return (location.line, finding.rule_id.upper()) in index.get(location.file, set())
