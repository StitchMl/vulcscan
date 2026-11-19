"""Bounded Flask/FastAPI object-level authorization scope heuristic.

Identify an HTTP path identifier flowing directly into an ORM primary-key
lookup when the handler lacks a recognizable owner/tenant/ACL constraint.
Never execute or import the target service.
"""
from __future__ import annotations

import ast
import re

from .models import Confidence, Finding, FlowStep, Location
from .rules import remediations_for, rule

_HTTP_METHODS = frozenset({"route", "get", "post", "put", "patch", "delete"})
_PATH_PARAM = re.compile(r"\{([A-Za-z_]\w*)\}|<(?:(?:int|uuid|string|path):)?([A-Za-z_]\w*)>")
_ID_NAME = re.compile(r"(?i)(?:^id$|(?:^|_)(?:id|pk|uuid)$|(?:Id|Pk|UUID)$)")
_SAFE_KEY = re.compile(r"(?i)(?:owner|tenant|principal|permission|authorize|acl|can_access|scope)")
_QUERY_GET = frozenset({"get", "get_or_404", "get_or_none", "get_by_id"})


def _location(path: str, node: ast.AST) -> Location:
    return Location(path, getattr(node, "lineno", 1), getattr(node, "col_offset", 0) + 1)


def _route(decorator: ast.AST) -> tuple[str, str] | None:
    if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
        return None
    method = decorator.func.attr.lower()
    if method not in _HTTP_METHODS or not decorator.args:
        return None
    candidate = decorator.args[0]
    if not isinstance(candidate, ast.Constant) or not isinstance(candidate.value, str):
        return None
    base = ast.unparse(decorator.func.value)
    if not re.fullmatch(r"(?:app|router|api|blueprint|bp|[a-z_]\w*_(?:router|bp))", base, re.I):
        return None
    return method.upper() if method != "route" else "ANY", candidate.value


def _lookup(node: ast.AST, parameter: str) -> bool:
    if not isinstance(node, ast.Call):
        return False
    if not isinstance(node.func, ast.Attribute) or node.func.attr not in _QUERY_GET:
        return False
    call = ast.unparse(node.func.value)
    if not call.endswith((".query", ".objects", ".session")):
        return False
    args = node.args
    if call.endswith(".session") and node.func.attr == "get":
        args = args[1:]
    return bool(args and isinstance(args[0], ast.Name) and args[0].id == parameter)


def _guard_node(node: ast.AST) -> bool:
    if isinstance(node, (ast.If, ast.Assert)):
        return bool(_SAFE_KEY.search(ast.unparse(node.test)))
    if not isinstance(node, ast.Call):
        return False
    if _SAFE_KEY.search(ast.unparse(node.func)):
        return True
    if isinstance(node.func, ast.Attribute) and node.func.attr in {"filter", "filter_by", "where"}:
        return bool(_SAFE_KEY.search(ast.unparse(node)))
    return False


def _scoped(function: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    return any(_guard_node(node) for node in ast.walk(function))


def _make_finding(
    path: str, source: str, name: str, method: str, route: str,
    decorator: ast.AST, call: ast.AST,
) -> Finding:
    definition = rule("AUTHZ-SCOPE-001")
    sink = _location(path, call)
    origin = _location(path, decorator)
    evidence = (ast.get_source_segment(source, call) or ast.unparse(call))[:300]
    return Finding(
        rule_id=definition.rule_id, name=definition.name,
        cwe=definition.cwe, severity=definition.severity,
        confidence=Confidence.MEDIUM, category=definition.category,
        language="Python", location=sink,
        source=origin, sink="unscoped ORM primary-key lookup",
        evidence=evidence, reason=definition.explanation,
        flow=[
            FlowStep("SOURCE", origin, method + " " + route, "HTTP path parameter " + name),
            FlowStep("SINK", sink, evidence, "ORM lookup using HTTP identifier without visible ownership scope."),
        ],
        remediations=remediations_for(definition.rule_id, evidence),
    )


def _route_findings(
    path: str, source: str, function: ast.FunctionDef | ast.AsyncFunctionDef,
    route_info: tuple[str, str], decorator: ast.AST, parameters: set[str],
) -> list[Finding]:
    method, route = route_info
    names = {
        name for match in _PATH_PARAM.finditer(route)
        for name in match.groups() if name
    }
    result = []
    for name in sorted(names & parameters):
        if not _ID_NAME.search(name):
            continue
        result.extend(
            _make_finding(path, source, name, method, route, decorator, call)
            for call in ast.walk(function) if _lookup(call, name)
        )
    return result


def _function_findings(
    path: str, source: str, function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[Finding]:
    routes = [
        (info, decorator)
        for decorator in function.decorator_list
        if (info := _route(decorator))
    ]
    if not routes or _scoped(function):
        return []
    parameters = {
        arg.arg for arg in (
            *function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs
        )
    }
    findings = []
    for info, decorator in routes:
        findings.extend(_route_findings(path, source, function, info, decorator, parameters))
    return findings


def analyze_route_authz(path: str, source: str) -> list[Finding]:
    try:
        tree = ast.parse(source, filename=path)
    except (SyntaxError, ValueError, MemoryError, RecursionError):
        return []
    findings = []
    for function in ast.walk(tree):
        if isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            findings.extend(_function_findings(path, source, function))
    return findings
