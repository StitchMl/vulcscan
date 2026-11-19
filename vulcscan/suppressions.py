"""Explicit, rule-scoped Python comment suppressions without executing target code."""
from __future__ import annotations

import io
import re
import tokenize
from typing import Any

from .models import Finding

_DIRECTIVE = re.compile(r"^#\s*vulcscan:ignore\s+([A-Z][A-Z0-9_-]+)\s*$", re.IGNORECASE)


def suppression_index(files: list[Any]) -> dict[str, set[tuple[int, str]]]:
    """Recognize directive comments only (not string literals).

    An inline comment suppresses its own line. A comment-only directive
    suppresses the next physical line, never an entire function or file.
    """
    indexed: dict[str, set[tuple[int, str]]] = {}
    for source in files:
        if source.language != "Python":
            continue
        lines = source.text.splitlines()
        active: set[tuple[int, str]] = set()
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
        if active:
            indexed[source.relative] = active
    return indexed


def is_suppressed(finding: Finding, index: dict[str, set[tuple[int, str]]]) -> bool:
    location = finding.location
    return (location.line, finding.rule_id.upper()) in index.get(location.file, set())
