"""Explicit, rule-scoped Python comment suppressions without executing target code."""
from __future__ import annotations

import io
import re
import tokenize
from typing import Any

from .models import Finding
from .source import JS_STYLE, blank_comments, split_lines

_DIRECTIVE = re.compile(r"^#\s*vulcscan:ignore\s+([A-Z][A-Z0-9_-]+)\s*$", re.IGNORECASE)
_JS_DIRECTIVE = re.compile(r"^//\s*vulcscan:ignore\s+([A-Z][A-Z0-9_-]+)\s*$", re.IGNORECASE)


def _javascript_directives(text: str) -> set[tuple[int, str]]:
    """Find real line comments outside strings, regexes and block comments."""
    clean = blank_comments(text, JS_STYLE)
    found: set[tuple[int, str]] = set()
    line, line_start, index = 1, 0, 0
    inside_block = False
    while index < len(text):
        if text[index] == "\\n":
            line += 1
            line_start = index + 1
            index += 1
            continue
        pair = text[index:index + 2]
        blanked = clean[index:index + 2] == "  "
        if inside_block:
            if pair == "*/":
                inside_block = False
                index += 2
                continue
        elif blanked and pair == "/*":
            inside_block = True
            index += 2
            continue
        elif blanked and pair == "//":
            end = text.find("\\n", index)
            end = len(text) if end < 0 else end
            match = _JS_DIRECTIVE.fullmatch(text[index:end].strip())
            if match:
                target = line if clean[line_start:index].strip() else line + 1
                found.add((target, match.group(1).upper()))
            index = end
            continue
        index += 1
    return found


def suppression_index(files: list[Any]) -> dict[str, set[tuple[int, str]]]:
    """Recognize directive comments only (not string literals).

    An inline comment suppresses its own line. A comment-only directive
    suppresses the next physical line, never an entire function or file.
    """
    indexed: dict[str, set[tuple[int, str]]] = {}
    for source in files:
        active: set[tuple[int, str]] = set()
        if source.language == "Python":
            lines = split_lines(source.text)
            try:
                tokens = tokenize.generate_tokens(io.StringIO(source.text).readline)
                for token in tokens:
                    if token.type != tokenize.COMMENT:
                        continue
                    match = _DIRECTIVE.fullmatch(token.string.strip())
                    if not match:
                        continue
                    row, column = token.start
                    prefix = lines[row - 1][:column]
                    target = row + 1 if not prefix.strip() else row
                    active.add((target, match.group(1).upper()))
            except (tokenize.TokenError, IndentationError, SyntaxError):
                continue
        elif source.language in {"JavaScript", "TypeScript"}:
            active.update(_javascript_directives(source.text))
        else:
            continue
        if active:
            indexed[source.relative] = active
    return indexed


def is_suppressed(finding: Finding, index: dict[str, set[tuple[int, str]]]) -> bool:
    location = finding.location
    return (location.line, finding.rule_id.upper()) in index.get(location.file, set())
