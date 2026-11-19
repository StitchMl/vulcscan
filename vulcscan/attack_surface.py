"""Conservative static mapping of explicitly declared HTTP endpoints.

This module parses source text only; it never imports or executes target code.
Unknown dynamic paths are intentionally omitted.
"""
from __future__ import annotations

import ast
import re
import shlex
from typing import Any

from .js_routes import resolve_handler
from .models import Finding
from .source import C_STYLE, blank_comments, code_mask

_HTTP_METHODS = frozenset({"get", "post", "put", "patch", "delete", "head", "options"})
_EXPRESS_ROUTE = re.compile(
    r"""\b(?:app|router)\s*\.\s*(get|post|put|patch|delete|head|options|all)\s*\(\s*(['"`])([^'"`\r\n]+)\2""",
    re.IGNORECASE,
)
_AUTH_NAMES = ("auth", "login_required", "permission", "jwt", "require_user")


def _literal(node: ast.AST) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _python_routes(relative: str, source: str) -> list[dict[str, Any]]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    endpoints: list[dict[str, Any]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        decorators = node.decorator_list
        auth = any(
            any(token in ast.unparse(decorator).lower() for token in _AUTH_NAMES)
            for decorator in decorators
        )
        for decorator in decorators:
            if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
                continue
            method = decorator.func.attr.lower()
            if method not in _HTTP_METHODS | {"route", "api_route", "websocket"}:
                continue
            path = _literal(decorator.args[0]) if decorator.args else None
            if path is None:
                continue
            if method in _HTTP_METHODS:
                methods = [method.upper()]
            elif method == "websocket":
                methods = ["WEBSOCKET"]
            else:
                methods = ["ANY"]
                for keyword in decorator.keywords:
                    if keyword.arg == "methods" and isinstance(keyword.value, (ast.List, ast.Tuple)):
                        listed = [_literal(value) for value in keyword.value.elts]
                        if listed and all(listed):
                            methods = sorted({value.upper() for value in listed if value})
            endpoints.append({
                "method": methods,
                "path": path,
                "file": relative,
                "line": decorator.lineno,
                "handler": node.name,
                "authentication": "present" if auth else "unknown",
            })
    return endpoints


def _javascript_routes(relative: str, source: str) -> list[dict[str, Any]]:
    endpoints: list[dict[str, Any]] = []
    for match in _EXPRESS_ROUTE.finditer(source):
        method, _, path = match.groups()
        # Only a direct handler identifier is eligible for static linkage.
        tail = source[match.end():]
        handler = re.match(r"\s*,\s*([A-Za-z_$][\w$]*)\s*[,)]", tail)
        endpoints.append({
            "method": ["ANY" if method.lower() == "all" else method.upper()],
            "path": path,
            "file": relative,
            "line": source.count("\n", 0, match.start()) + 1,
            "handler": handler.group(1) if handler else None,
            "authentication": "unknown",
        })
    return endpoints


_GIN_ROUTE = re.compile(
    r"\b(?:r|router|engine|api|group|v1|v2)\s*\.\s*"
    r"(?P<method>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|Any|Handle)\s*"
    r"\(\s*(?P<quote>[\"\x60])(?P<path>[^\"\x60\r\n]+)(?P=quote)"
)
_GIN_HANDLER = re.compile(r"^\s*,\s*(?P<handler>[A-Za-z_]\w*)\s*\)")
_GIN_MIDDLEWARE_HANDLER = re.compile(
    r"^\s*,\s*(?P<middleware>[A-Za-z_]\w*)\s*,\s*(?P<handler>[A-Za-z_]\w*)\s*\)"
)


def _gin_routes(relative: str, source: str) -> list[dict[str, Any]]:
    """Capture direct literal Gin registrations, not dynamic Group prefixes."""
    if not (
        re.search(r"(?m)^[ \t]*import\b[\s\S]{0,2000}github\.com/gin-gonic/gin", source)
        or re.search(r"\bgin\s*\.\s*(?:Default|New)\s*\(", source)
    ):
        return []
    visible = blank_comments(source, C_STYLE)
    mask = code_mask(source, C_STYLE)
    endpoints: list[dict[str, Any]] = []
    for match in _GIN_ROUTE.finditer(visible):
        # Do not parse route-like text embedded inside Go string literals.
        if mask[match.start():match.start() + 1] != visible[match.start():match.start() + 1]:
            continue
        method, path = match.group("method"), match.group("path")
        if not path.startswith("/") or path.startswith("//"):
            continue
        if method == "Handle":
            # Gin.Handle(method, path, handler) has a different signature.
            continue
        tail = visible[match.end():match.end() + 200]
        direct = _GIN_HANDLER.match(tail)
        middleware = _GIN_MIDDLEWARE_HANDLER.match(tail)
        handler = direct.group("handler") if direct else (
            middleware.group("handler") if middleware else None
        )
        auth = "unknown"
        if middleware and any(
            token in middleware.group("middleware").casefold() for token in _AUTH_NAMES
        ):
            auth = "present"
        endpoints.append({
            "method": ["ANY" if method == "Any" else method],
            "path": path,
            "file": relative,
            "line": source.count("\n", 0, match.start()) + 1,
            "handler": handler,
            "authentication": auth,
        })
    return endpoints


_QUERY_PARAM = re.compile(
    r"""(?:request\.args(?:\.get)?\(\s*['"]([A-Za-z_]\w*)['"]|"""
    r"""request\.args\[\s*['"]([A-Za-z_]\w*)['"]\s*\]|"""
    r"""req\.query\.([A-Za-z_]\w*))"""
)


def _verification_curl(route: dict[str, Any], findings: list[Finding]) -> str | None:
    """Generate a copyable, never-executed GET canary for confidently linked traces.

    No placeholder substitution, request body, credentials or state-changing
    methods are inferred. Do not guess when the route is dynamic.
    """
    path = route["path"]
    if route["method"] != ["GET"] or not path.startswith("/") or any(
        token in path for token in ("<", ">", "{", "}", ":", "?", "#", "\\n", "\\r", " ")
    ) or path.startswith("//") or any(ord(char) < 32 for char in path):
        return None
    parameters: set[str] = set()
    for finding in findings:
        for step in finding.flow:
            if step.kind.upper() != "SOURCE":
                continue
            match = _QUERY_PARAM.search(step.code)
            if match:
                parameters.add(next(value for value in match.groups() if value))
    if not parameters:
        return None
    query = "&".join(name + "=VULCSCAN_CANARY" for name in sorted(parameters))
    url = "http://127.0.0.1:8000" + path + "?" + query
    return "curl --silent --show-error --max-time 5 " + shlex.quote(url)


def map_attack_surface(files: list[Any], findings: list[Finding]) -> list[dict[str, Any]]:
    """Return stable endpoint metadata, with conservative same-file finding references."""
    routes: list[dict[str, Any]] = []
    for source in files:
        if source.language == "Python":
            routes.extend(_python_routes(source.relative, source.text))
        elif source.language in {"JavaScript", "TypeScript"}:
            routes.extend(_javascript_routes(source.relative, source.text))
        elif source.language == "Go":
            routes.extend(_gin_routes(source.relative, source.text))
    modules = {
        source.relative: source for source in files
        if source.language in {"JavaScript", "TypeScript"}
    }
    for route in routes:
        handler_file = route["file"]
        handler_name = route["handler"]
        if handler_file in modules and handler_name:
            resolved = resolve_handler(
                handler_file, modules[handler_file].text, handler_name, modules
            )
            if resolved is None:
                handler_name = None
            else:
                handler_file, handler_name = resolved
                if handler_file != route["file"]:
                    route["handler_file"] = handler_file
        matches = [
            finding for finding in findings
            if handler_name is not None
            and finding.location.file == handler_file
            and (
                finding.location.function == handler_name
                or (finding.location.function or "").endswith("." + handler_name)
            )
        ]
        route["finding_rules"] = sorted({finding.rule_id for finding in matches})
        probe = _verification_curl(route, matches)
        if probe is not None:
            route["verify_curl"] = probe
    return sorted(routes, key=lambda route: (route["file"].casefold(), route["line"], route["path"], route["method"]))
