"""Conservative static inventory of Spring MVC literal HTTP mapping annotations.

Only controller classes with literal class/method mapping paths are recognized.
No Java bytecode or source is executed.
"""
from __future__ import annotations

import re
from typing import Any

from .source import C_STYLE, blank_comments, code_mask

_CLASS = re.compile(
    r"(?P<annotations>(?:@[A-Za-z_]\w*(?:\s*\([^()\r\n]*\))?\s*){1,10})"
    r"(?:(?:public|abstract|final)\s+)*class\s+(?P<name>[A-Za-z_]\w*)\b"
)
_MAPPING = re.compile(
    r"@(?P<type>Get|Post|Put|Patch|Delete|Request)Mapping\s*\(\s*"
    r"(?:(?:value|path)\s*=\s*)?\"(?P<path>[^\"\r\n]+)\""
    r"(?P<extra>[^)\r\n]{0,150})\)"
)
_METHOD = re.compile(
    r"(?:public|protected)\s+(?:(?:static|final|synchronized)\s+)*"
    r"[\w.<>,? \[\]]{1,120}\s+(?P<name>[A-Za-z_]\w*)\s*\("
)
_CLASS_PREFIX = re.compile(
    r"@RequestMapping\s*\(\s*(?:(?:value|path)\s*=\s*)?\"(?P<path>/[^\"\r\n]*)\"\s*\)"
)
_AUTH = re.compile(r"@(?:PreAuthorize|PostAuthorize|Secured|RolesAllowed|RequiresPermissions)\b")
_METHOD_KIND = {
    "Get": ["GET"], "Post": ["POST"], "Put": ["PUT"],
    "Patch": ["PATCH"], "Delete": ["DELETE"],
}


_NEXT_MAPPING = re.compile(r"@(?:Get|Post|Put|Patch|Delete|Request)Mapping\b")
_REQUEST_METHOD = re.compile(r"RequestMethod\.(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)")
_CONTROLLER_ANNOTATION = re.compile(r"@(?:RestController|Controller)\b")


def _closing_brace(mask: str, opening: int) -> int | None:
    depth = 0
    for offset in range(opening, len(mask)):
        if mask[offset] == "{":
            depth += 1
        elif mask[offset] == "}":
            depth -= 1
            if depth == 0:
                return offset
    return None


def _controller_class(visible: str, mask: str, candidate: re.Match[str]) -> tuple[int, int, str, bool] | None:
    annotations = candidate.group("annotations")
    if not _CONTROLLER_ANNOTATION.search(annotations):
        return None
    # Classes with nonliteral RequestMapping cannot be mapped reliably.
    prefix = _CLASS_PREFIX.search(annotations)
    dynamic_prefix = "@RequestMapping" in annotations and prefix is None
    opening = mask.find("{", candidate.end(), min(len(mask), candidate.end() + 300))
    if opening < 0:
        return None
    closing = _closing_brace(mask, opening)
    if closing is None:
        return None
    return opening, closing, prefix.group("path") if prefix else "", dynamic_prefix


def _mapping_methods(route: re.Match[str]) -> list[str]:
    if route.group("type") == "Request":
        methods = sorted(set(_REQUEST_METHOD.findall(route.group("extra"))))
        return methods or ["ANY"]
    return _METHOD_KIND[route.group("type")]


def _mapping_tail(visible: str, route: re.Match[str], class_end: int) -> str:
    # Class-level @RequestMapping appears before class declarations,
    # so there must be a method signature after the mapping annotation.
    tail = visible[route.end():min(route.end() + 600, class_end)]
    next_mapping = _NEXT_MAPPING.search(tail)
    return tail[:next_mapping.start()] if next_mapping else tail


def _route_entry(
    path: str,
    source: str,
    visible: str,
    route: re.Match[str],
    class_info: tuple[int, int, str, bool],
) -> dict[str, Any] | None:
    _, class_end, prefix, dynamic = class_info
    if dynamic:
        return None
    tail = _mapping_tail(visible, route, class_end)
    method = _METHOD.search(tail)
    if method is None:
        return None
    segment = route.group("path")
    if not segment.startswith("/") or segment.startswith("//"):
        return None
    combined = prefix.rstrip("/") + segment if prefix else segment
    auth = "present" if _AUTH.search(tail[:method.start()]) else "unknown"
    return {
        "method": _mapping_methods(route),
        "path": combined,
        "file": path,
        "line": source.count("\n", 0, route.start()) + 1,
        "handler": method.group("name"),
        "authentication": auth,
    }


def spring_routes(path: str, source: str) -> list[dict[str, Any]]:
    visible = blank_comments(source, C_STYLE)
    mask = code_mask(source, C_STYLE)
    classes = []
    for candidate in _CLASS.finditer(visible):
        info = _controller_class(visible, mask, candidate)
        if info is not None:
            classes.append(info)
    if not classes:
        return []

    output: list[dict[str, Any]] = []
    for route in _MAPPING.finditer(visible):
        if mask[route.start()] != "@":
            continue
        candidates = [item for item in classes if item[0] < route.start() < item[1]]
        if not candidates:
            continue
        entry = _route_entry(path, source, visible, route, candidates[-1])
        if entry is not None:
            output.append(entry)
    return output
