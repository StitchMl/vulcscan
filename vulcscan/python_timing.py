"""Bounded detection of secret comparisons against direct HTTP input."""
from __future__ import annotations

import ast
import re

from .models import Confidence, Finding, FlowStep, Location
from .rules import remediations_for, rule

_SECRET = re.compile(r"(?i)(?:token|secret|hmac|signature|digest|api_key|apikey|mac|auth_hash|password_hash)")
_REMOTE = re.compile(r"^(?:flask\.)?request\.(?:args|form|values|json|headers|cookies|body|data)(?:\b|[\[(.])")


class _Visitor(ast.NodeVisitor):
    def __init__(self, path: str, source: str) -> None:
        self.path = path
        self.source = source
        self.remote: dict[str, tuple[Location, str]] = {}
        self.findings: list[Finding] = []

    def _loc(self, node: ast.AST) -> Location:
        return Location(self.path, getattr(node, "lineno", 1), getattr(node, "col_offset", 0) + 1)

    def _origin(self, node: ast.AST) -> tuple[Location, str] | None:
        if isinstance(node, ast.Name):
            return self.remote.get(node.id)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {"int", "float", "bool"}:
            return None
        expression = ast.unparse(node)
        if _REMOTE.match(expression):
            return self._loc(node), expression[:250]
        return None

    def _secret(self, node: ast.AST) -> bool:
        if isinstance(node, (ast.Name, ast.Attribute)):
            return bool(_SECRET.search(ast.unparse(node)))
        return False

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        origin = self._origin(node.value)
        for target in node.targets:
            if isinstance(target, ast.Name):
                if origin is None:
                    self.remote.pop(target.id, None)
                else:
                    self.remote[target.id] = origin

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self.visit(node.value)
        if isinstance(node.target, ast.Name):
            origin = self._origin(node.value) if node.value is not None else None
            if origin is None:
                self.remote.pop(node.target.id, None)
            else:
                self.remote[node.target.id] = origin

    def visit_Compare(self, node: ast.Compare) -> None:
        if len(node.ops) != 1 or not isinstance(node.ops[0], (ast.Eq, ast.NotEq)):
            self.generic_visit(node)
            return
        left, right = node.left, node.comparators[0]
        origin = self._origin(left) if self._secret(right) else None
        if origin is None and self._secret(left):
            origin = self._origin(right)
        if origin is not None:
            definition = rule("PY-TIMING-001")
            location = self._loc(node)
            source_location, source_code = origin
            evidence = (ast.get_source_segment(self.source, node) or ast.unparse(node))[:350]
            self.findings.append(Finding(
                rule_id=definition.rule_id, name=definition.name, cwe=definition.cwe,
                severity=definition.severity, confidence=Confidence.MEDIUM,
                category=definition.category, language="Python",
                location=location, sink="secret equality comparison", evidence=evidence,
                reason=definition.explanation, source=source_location,
                flow=[
                    FlowStep("SOURCE", source_location, source_code, "HTTP-provided comparison value."),
                    FlowStep("SINK", location, evidence, "Secret compared with non-constant-time equality."),
                ],
                remediations=remediations_for(definition.rule_id, evidence),
            ))
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        previous = self.remote
        self.remote = {}
        for statement in node.body:
            self.visit(statement)
        self.remote = previous

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_If(self, node: ast.If) -> None:
        self.visit(node.test)
        old = dict(self.remote)
        for statement in node.body:
            self.visit(statement)
        self.remote = dict(old)
        for statement in node.orelse:
            self.visit(statement)
        self.remote = old


def analyze_timing_comparisons(path: str, source: str) -> list[Finding]:
    try:
        tree = ast.parse(source, filename=path)
    except (SyntaxError, ValueError, MemoryError, RecursionError):
        return []
    visitor = _Visitor(path, source)
    visitor.visit(tree)
    return visitor.findings
