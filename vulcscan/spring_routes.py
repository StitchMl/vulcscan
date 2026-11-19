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


def spring_routes(path: str, source: str) -> list[dict[str, Any]]:
    visible = blank_comments(source, C_STYLE)
    mask = code_mask(source, C_STYLE)
    classes = []
    for candidate in _CLASS.finditer(visible):
        annotations = candidate.group("annotations")
        if not re.search(r"@(?:RestController|Controller)\b", annotations):
            continue
        # Classes with nonliteral RequestMapping cannot be mapped reliably.
        dynamic_prefix = "@RequestMapping" in annotations and _CLASS_PREFIX.search(annotations) is None
        prefix = _CLASS_PREFIX.search(annotations)
        classes.append((candidate.end(), prefix.group("path") if prefix else "", dynamic_prefix))
    if not classes:
        return []

    output: list[dict[str, Any]] = []
    for route in _MAPPING.finditer(visible):
        if mask[route.start()] != "@":
            continue
        candidates = [item for item in classes if item[0] <= route.start()]
        if not candidates:
            continue
        class_end, prefix, dynamic = candidates[-1]
        if dynamic:
            continue
        # Class-level @RequestMapping appears before class declarations,
        # so there must be a method signature after the mapping annotation.
        tail = visible[route.end():route.end() + 600]
        next_mapping = re.search(r"@(?:Get|Post|Put|Patch|Delete|Request)Mapping\b", tail)
        if next_mapping:
            tail = tail[:next_mapping.start()]
        method = _METHOD.search(tail)
        if method is None:
            continue
        segment = route.group("path")
        if not segment.startswith("/") or segment.startswith("//"):
            continue
        combined = prefix.rstrip("/") + segment if prefix else segment
        if route.group("type") == "Request":
            methods = sorted(set(re.findall(r"RequestMethod\.(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)", route.group("extra"))))
            methods = methods or ["ANY"]
        else:
            methods = _METHOD_KIND[route.group("type")]
        auth = "present" if _AUTH.search(tail[:method.start()]) else "unknown"
        output.append({
            "method": methods,
            "path": combined,
            "file": path,
            "line": source.count("\n", 0, route.start()) + 1,
            "handler": method.group("name"),
            "authentication": auth,
        })
    return output
