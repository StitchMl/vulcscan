"""Conservative PHP Laravel/Slim route discovery for literal path declarations."""
from __future__ import annotations

import re
from typing import Any

from .source import PHP_STYLE, blank_comments, code_mask

_LARAVEL = re.compile(
    r"\bRoute\s*::\s*(?P<method>get|post|put|patch|delete|options|any|match)\s*"
    r"\(\s*(?P<quote>['\"])(?P<path>[^'\"\r\n]+)(?P=quote)\s*,",
    re.IGNORECASE,
)
_SLIM = re.compile(
    r"\$(?:app|router)\s*->\s*(?P<method>get|post|put|patch|delete|options|any)\s*"
    r"\(\s*(?P<quote>['\"])(?P<path>[^'\"\r\n]+)(?P=quote)\s*,",
    re.IGNORECASE,
)
_CONTROLLER = re.compile(
    r"^\s*\[\s*(?P<controller>[A-Za-z_][\w\\]*)::class\s*,\s*"
    r"(?P<quote>['\"])(?P<handler>[A-Za-z_]\w*)(?P=quote)\s*\]"
)
_OLD_ACTION = re.compile(
    r"^\s*(?P<quote>['\"])(?P<controller>[A-Za-z_][\w\\]*)@"
    r"(?P<handler>[A-Za-z_]\w*)(?P=quote)"
)
_NAMED_ACTION = re.compile(r"^\s*(?P<name>[A-Za-z_]\w*)\s*[,)]")


_MIDDLEWARE_AUTH = re.compile(
    r"""->\s*middleware\s*\(\s*['\"](?:auth|auth:[^'\"]+)['\"]\s*\)""",
    re.IGNORECASE,
)


def _php_handler(after: str, mode: str) -> str | None:
    ctrl = _CONTROLLER.match(after)
    if ctrl:
        return ctrl.group("controller").split("\\")[-1] + "." + ctrl.group("handler")
    old = _OLD_ACTION.match(after)
    if old:
        return old.group("controller").split("\\")[-1] + "." + old.group("handler")
    named = _NAMED_ACTION.match(after) if mode == "slim" else None
    return named.group("name") if named else None


def _php_has_auth(visible: str, start: int) -> bool:
    # Only inspect the current physical line for a directly chained
    # middleware call. Unknown middleware does not prove auth.
    line_end = visible.find("\n", start)
    line_end = len(visible) if line_end < 0 else line_end
    return bool(_MIDDLEWARE_AUTH.search(visible[start:line_end]))


def _php_route_ok(route: str) -> bool:
    return route.startswith("/") and not route.startswith("//") and not any(ord(c) < 32 for c in route)


def _php_in_code(mask: str, match: re.Match[str], mode: str) -> bool:
    width, expected = (1, "$") if mode == "slim" else (5, "Route")
    return mask[match.start():match.start() + width].strip() == expected


def php_routes(relative: str, source: str) -> list[dict[str, Any]]:
    visible = blank_comments(source, PHP_STYLE)
    mask = code_mask(source, PHP_STYLE)
    slim_enabled = bool(re.search(r"(?i)\bSlim\\(?:Factory|App)\b|AppFactory\s*::\s*create\s*\(", visible))
    results: list[dict[str, Any]] = []
    patterns = [(_LARAVEL, "laravel")]
    if slim_enabled:
        patterns.append((_SLIM, "slim"))
    for pattern, mode in patterns:
        for match in pattern.finditer(visible):
            route = match.group("path")
            method = match.group("method").upper()
            # MATCH: first argument is an array in Laravel match routes, outside this parser.
            if not _php_in_code(mask, match, mode) or not _php_route_ok(route) or method == "MATCH":
                continue
            after = visible[match.end():match.end() + 320]
            results.append({
                "method": ["ANY" if method == "ANY" else method],
                "path": route,
                "file": relative,
                "line": source.count("\n", 0, match.start()) + 1,
                "handler": _php_handler(after, mode),
                "authentication": "present" if _php_has_auth(visible, match.end()) else "unknown",
            })
    return results
