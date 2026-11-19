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
_ID_NAME = re.compile(r"(?i)(?:^id$|(?:^|_)(?:id|pk|uuid)$|(?:Id|ID|Pk|UUID)$)")
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
    if not re.fullmatch(r"(?:app|router|api|blueprint|bp|[A-Za-z_]\w*_(?:router|bp))", base, re.I):
        return None
    return method.upper() if method != "route" else "ANY", candidate.value


def _lookup(node: ast.AST, parameter: str) -> bool:
    if not isinstance(node, ast.Call):
        return False
    if not isinstance(node.func, ast.Attribute) or node.func.attr not in _QUERY_GET:
        return False
    call = ast.unparse(node.func.value)
    if not (call.endswith(".query") or call.endswith(".objects") or call.endswith(".session")):
        return False
    args = node.args
    if call.endswith(".session") and node.func.attr == "get":
        args = args[1:]
    return bool(args and isinstance(args[0], ast.Name) and args[0].id == parameter)


def _scoped(function: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for node in ast.walk(function):
        if isinstance(node, (ast.If, ast.Assert)):
            condition = ast.unparse(node.test)
            if _SAFE_KEY.search(condition):
                return True
        if isinstance(node, ast.Call):
            call = ast.unparse(node.func)
            if _SAFE_KEY.search(call):
                return True
            if isinstance(node.func, ast.Attribute) and node.func.attr in {"filter", "filter_by", "where"}:
                if _SAFE_KEY.search(ast.unparse(node)):
                    return True
    return False


def analyze_route_authz(path: str, source: str) -> list[Finding]:
    try:
        tree = ast.parse(source, filename=path)
    except (SyntaxError, ValueError, MemoryError, RecursionError):
        return []
    definition = rule("AUTHZ-SCOPE-001")
    findings: list[Finding] = []
    for function in ast.walk(tree):
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        routes = [item for decorator in function.decorator_list if (item := _route(decorator))]
        if not routes or _scoped(function):
            continue
        parameters = {arg.arg for arg in (*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs)}
        for method, route in routes:
            names = {value for match in _PATH_PARAM.finditer(route) for value in match.groups() if value}
            for name in sorted(names):
                if name not in parameters or not _ID_NAME.search(name):
                    continue
                for node in ast.walk(function):
                    if not _lookup(node, name):
                        continue
                    sink = _location(path, node)
                    route_node = function.decorator_list[routes.index((method, route))]
                    origin = _location(path, route_node)
                    evidence = (ast.get_source_segment(source, node) or ast.unparse(node))[:300]
                    findings.append(Finding(
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
                    ))
    return findings
