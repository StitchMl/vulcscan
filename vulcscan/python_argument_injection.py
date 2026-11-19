"""Conservative CWE-88 detection for network-controlled subprocess arguments.

The target program is parsed but never imported or executed. Only direct,
constant program lists and explicit HTTP request sources are considered.
"""
from __future__ import annotations

import ast
import os
import re

from .models import Confidence, Finding, FlowStep, Location
from .rules import remediations_for, rule

_PROGRAMS = frozenset({"git", "tar", "curl", "ssh", "rsync", "find", "openssl", "scp"})
_SUBPROCESS = frozenset({"run", "call", "check_call", "check_output", "Popen"})
_REMOTE_ACCESS = re.compile(
    r"^(?:request|flask\.request)\."
    r"(?:args|form|values|json|files|cookies|headers|query_params)"
    r"(?:\.|\[|\(|$)"
)


class _Walker(ast.NodeVisitor):
    def __init__(self, relative: str, text: str, imports: dict[str, str]) -> None:
        self.relative = relative
        self.text = text
        self.imports = imports
        self.sources: dict[str, tuple[Location, str]] = {}
        self.findings: list[Finding] = []

    def _location(self, node: ast.AST) -> Location:
        return Location(
            self.relative,
            getattr(node, "lineno", 1),
            getattr(node, "col_offset", 0) + 1,
            getattr(node, "end_lineno", None),
            getattr(node, "end_col_offset", None),
        )

    def _source(self, node: ast.AST) -> tuple[Location, str] | None:
        if isinstance(node, ast.Name):
            return self.sources.get(node.id)
        # Converting a remote value to a number prevents option injection.
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {
            "int", "float", "bool",
        }:
            return None
        expression = ast.unparse(node)
        if _REMOTE_ACCESS.match(expression):
            return self._location(node), expression[:250]
        return None

    def _canonical(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return self.imports.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            return self._canonical(node.value) + "." + node.attr
        return ""

    def _program_call(self, node: ast.Call) -> tuple[str, list[ast.expr]] | None:
        canonical = self._canonical(node.func)
        if canonical.startswith("subprocess.") and canonical.rsplit(".", 1)[1] in _SUBPROCESS:
            if not node.args or not isinstance(node.args[0], (ast.List, ast.Tuple)):
                return None
            elements = list(node.args[0].elts)
        elif canonical == "asyncio.create_subprocess_exec":
            elements = list(node.args)
        else:
            return None
        if not elements or not isinstance(elements[0], ast.Constant) or not isinstance(elements[0].value, str):
            return None
        program = elements[0].value.replace("\\", "/").rsplit("/", 1)[-1].lower()
        if program.endswith(".exe"):
            program = program[:-4]
        if program not in _PROGRAMS:
            return None
        if any(
            keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True
            for keyword in node.keywords
        ):
            return None
        return program, elements

    def visit_Call(self, node: ast.Call) -> None:
        parsed = self._program_call(node)
        if parsed is not None:
            program, elements = parsed
            # Only a leading-hyphen option from an HTTP source is relevant.
            # A preceding literal -- separates options for supported commands.
            for index, expression in enumerate(elements[1:], 1):
                if any(
                    isinstance(item, ast.Constant) and item.value == "--"
                    for item in elements[1:index]
                ):
                    continue
                source = self._source(expression)
                if source is None:
                    continue
                definition = rule("PY-ARG-001")
                sink_location = self._location(expression)
                source_location, source_code = source
                call_text = (ast.get_source_segment(self.text, node) or ast.unparse(node))[:350]
                self.findings.append(Finding(
                    rule_id=definition.rule_id,
                    name=definition.name,
                    cwe=definition.cwe,
                    severity=definition.severity,
                    confidence=Confidence.MEDIUM,
                    category=definition.category,
                    language="Python",
                    location=sink_location,
                    sink=f"{program} argument {index}",
                    evidence=call_text,
                    reason=definition.explanation,
                    source=source_location,
                    flow=[
                        FlowStep("SOURCE", source_location, source_code, "HTTP request argument source."),
                        FlowStep("SINK", sink_location, call_text, f"Value is passed to {program} without an option terminator."),
                    ],
                    remediations=remediations_for(definition.rule_id, call_text),
                ))
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        source = self._source(node.value)
        for target in node.targets:
            if isinstance(target, ast.Name):
                if source is None:
                    self.sources.pop(target.id, None)
                else:
                    self.sources[target.id] = source

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self.visit(node.value)
        if isinstance(node.target, ast.Name):
            source = self._source(node.value) if node.value is not None else None
            if source is None:
                self.sources.pop(node.target.id, None)
            else:
                self.sources[node.target.id] = source

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        previous = self.sources
        self.sources = {}
        for statement in node.body:
            self.visit(statement)
        self.sources = previous

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_If(self, node: ast.If) -> None:
        self.visit(node.test)
        saved = dict(self.sources)
        for statement in node.body:
            self.visit(statement)
        self.sources = dict(saved)
        for statement in node.orelse:
            self.visit(statement)
        self.sources = saved


def analyze_argument_injection(relative: str, text: str) -> list[Finding]:
    try:
        tree = ast.parse(text, filename=relative)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return []
    imports: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for item in node.names:
                if item.name in {"subprocess", "asyncio"}:
                    imports[item.asname or item.name] = item.name
        elif isinstance(node, ast.ImportFrom) and node.module in {"subprocess", "asyncio"}:
            for item in node.names:
                imports[item.asname or item.name] = node.module + "." + item.name
    walker = _Walker(relative, text, imports)
    walker.visit(tree)
    return walker.findings
