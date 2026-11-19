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
            # blank_comments preserves offsets and retains string contents.
            clean = blank_comments(source.text, JS_STYLE)
            for row, (line, visible) in enumerate(
                zip(split_lines(source.text), split_lines(clean), strict=True), 1
            ):
                comment = re.search(r"//.*$", line)
                if comment is None:
                    continue
                if visible[comment.start():comment.start() + 2] != "  ":
                    continue
                match = _JS_DIRECTIVE.fullmatch(comment.group(0).strip())
                if match is None:
                    continue
                prefix = visible[:comment.start()]
                target = row if prefix.strip() else row + 1
                active.add((target, match.group(1).upper()))
        else:
            continue
        if active:
            indexed[source.relative] = active
    return indexed


def is_suppressed(finding: Finding, index: dict[str, set[tuple[int, str]]]) -> bool:
    location = finding.location
    return (location.line, finding.rule_id.upper()) in index.get(location.file, set())
