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


def php_routes(relative: str, source: str) -> list[dict[str, Any]]:
    visible = blank_comments(source, PHP_STYLE)
    mask = code_mask(source, PHP_STYLE)
    slim_enabled = bool(re.search(r"(?i)\bSlim\\(?:Factory|App)\b|AppFactory\s*::\s*create\s*\(", visible))
    results: list[dict[str, Any]] = []
    for pattern, mode in ((_LARAVEL, "laravel"), (_SLIM, "slim")):
        if mode == "slim" and not slim_enabled:
            continue
        for match in pattern.finditer(visible):
            if mask[match.start():match.start() + (1 if mode == "slim" else 5)].strip() != (
                "$" if mode == "slim" else "Route"
            ):
                continue
            route = match.group("path")
            if not route.startswith("/") or route.startswith("//") or any(ord(c) < 32 for c in route):
                continue
            method = match.group("method").upper()
            if method == "MATCH":
                # First argument is an array in Laravel match routes, outside this parser.
                continue
            after = visible[match.end():match.end() + 320]
            ctrl = _CONTROLLER.match(after)
            old = _OLD_ACTION.match(after)
            named = _NAMED_ACTION.match(after) if mode == "slim" else None
            if ctrl:
                handler = ctrl.group("controller").split("\\")[-1] + "." + ctrl.group("handler")
            elif old:
                handler = old.group("controller").split("\\")[-1] + "." + old.group("handler")
            elif named:
                handler = named.group("name")
            else:
                handler = None

            # Only inspect the current physical line for a directly chained
            # middleware call. Unknown middleware does not prove auth.
            line_end = visible.find("\n", match.end())
            line_end = len(visible) if line_end < 0 else line_end
            statement = visible[match.end():line_end]
            auth = bool(re.search(
                r"""->\s*middleware\s*\(\s*['\"](?:auth|auth:[^'\"]+)['\"]\s*\)""",
                statement,
                re.IGNORECASE,
            ))
            results.append({
                "method": ["ANY" if method == "ANY" else method],
                "path": route,
                "file": relative,
                "line": source.count("\n", 0, match.start()) + 1,
                "handler": handler,
                "authentication": "present" if auth else "unknown",
            })
    return results
