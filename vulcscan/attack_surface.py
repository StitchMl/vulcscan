"""Conservative static mapping of explicitly declared HTTP endpoints.

This module parses source text only; it never imports or executes target code.
Unknown dynamic paths are intentionally omitted.
"""
from __future__ import annotations

import ast
import re
import shlex
from urllib.parse import urlencode
from typing import Any

from .models import Finding

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
        endpoints.append({
            "method": ["ANY" if method.lower() == "all" else method.upper()],
            "path": path,
            "file": relative,
            "line": source.count("\n", 0, match.start()) + 1,
            "handler": None,
            "authentication": "unknown",
        })
    return endpoints


_QUERY_PARAM = re.compile(
    r"""(?:request\\.args(?:\\.get)?\\(\\s*['"]([A-Za-z_]\\w*)['"]|"""
    r"""request\\.args\\[\\s*['"]([A-Za-z_]\\w*)['"]\\s*\\]|"""
    r"""req\\.query\\.([A-Za-z_]\\w*))"""
)


def _verification_curl(route: dict[str, Any], findings: list[Finding]) -> str | None:
    """Generate a copyable, never-executed GET canary for confidently linked traces.

    No placeholder substitution, request body, credentials or state-changing
    methods are inferred. Do not guess when the route is dynamic.
    """
    path = route["path"]
    if route["method"] != ["GET"] or not path.startswith("/") or any(
        token in path for token in ("<", ">", "{", "}", ":", "?", "#", "\\n", "\\r", " ")
    ) or path.startswith("//"):
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
    query = urlencode([(name, "VULCSCAN_CANARY") for name in sorted(parameters)])
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
    for route in routes:
        matches = [
            finding for finding in findings
            if finding.location.file == route["file"]
            and (route["handler"] is not None and (
                finding.location.function == route["handler"]
                or (finding.location.function or "").endswith("." + route["handler"])
            ))
        ]
        route["finding_rules"] = sorted({finding.rule_id for finding in matches})
        probe = _verification_curl(route, matches)
        if probe is not None:
            route["verify_curl"] = probe
    return sorted(routes, key=lambda route: (route["file"].casefold(), route["line"], route["path"], route["method"]))
