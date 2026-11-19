"""Conservative AST audit of uploaded TAR archives extracted without filters.

Archive APIs are recognized statically. No user code or archive bytes are read
or executed; only explicit HTTP-derived TAR archive handles are considered.
"""
from __future__ import annotations

import ast
import re

from .models import Confidence, Finding, FlowStep, Location
from .rules import remediations_for, rule

_UPLOAD = re.compile(
    r"^(?:flask\.)?request\.(?:files|stream|data|body|get_data)(?:\b|[\[(.])"
)


class _TarWalker(ast.NodeVisitor):
    def __init__(self, path: str, text: str, imports: dict[str, str]) -> None:
        self.path = path
        self.text = text
        self.imports = imports
        self.inputs: dict[str, tuple[Location, str]] = {}
        self.archives: dict[str, tuple[Location, str]] = {}
        self.findings: list[Finding] = []

    def _location(self, node: ast.AST) -> Location:
        return Location(
            self.path,
            getattr(node, "lineno", 1),
            getattr(node, "col_offset", 0) + 1,
            getattr(node, "end_lineno", None),
        )

    def _canonical(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return self.imports.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            return self._canonical(node.value) + "." + node.attr
        return ""

    def _upload(self, node: ast.AST) -> tuple[Location, str] | None:
        if isinstance(node, ast.Name):
            return self.inputs.get(node.id)
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            tracked = self.inputs.get(node.value.id)
            if tracked is not None:
                return tracked
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            return self._upload(node.func.value)
        if isinstance(node, ast.Subscript):
            tracked = self._upload(node.value)
            if tracked is not None:
                return tracked
        expression = ast.unparse(node)
        if _UPLOAD.match(expression):
            return self._location(node), expression[:250]
        return None

    def _opened(self, node: ast.AST) -> tuple[Location, str] | None:
        if not isinstance(node, ast.Call):
            return None
        if self._canonical(node.func) not in {"tarfile.open", "tarfile.TarFile.open"}:
            return None
        values = [
            argument.value for argument in node.keywords
            if argument.arg in {"fileobj", "name"}
        ]
        if not values and node.args:
            values = [node.args[0]]
        for value in values:
            origin = self._upload(value)
            if origin is not None:
                return origin
        return None

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        upload = self._upload(node.value)
        tar = self._opened(node.value)
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            self.inputs.pop(target.id, None)
            self.archives.pop(target.id, None)
            if upload is not None:
                self.inputs[target.id] = upload
            if tar is not None:
                self.archives[target.id] = tar

    def visit_With(self, node: ast.With) -> None:
        prior_inputs = dict(self.inputs)
        prior_archives = dict(self.archives)
        for item in node.items:
            self.visit(item.context_expr)
            if isinstance(item.optional_vars, ast.Name):
                origin = self._opened(item.context_expr)
                if origin is not None:
                    self.archives[item.optional_vars.id] = origin
        for statement in node.body:
            self.visit(statement)
        self.inputs, self.archives = prior_inputs, prior_archives

    visit_AsyncWith = visit_With

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        old_inputs, old_archives = self.inputs, self.archives
        self.inputs, self.archives = {}, {}
        for statement in node.body:
            self.visit(statement)
        self.inputs, self.archives = old_inputs, old_archives

    visit_AsyncFunctionDef = visit_FunctionDef

    def _unfiltered_archive(self, node: ast.Call) -> str | None:
        """Name of the tracked archive this call extracts without a filter."""
        func = node.func
        if not (isinstance(func, ast.Attribute) and func.attr in {"extractall", "extract"}):
            return None
        if not (isinstance(func.value, ast.Name) and func.value.id in self.archives):
            return None
        # Explicit filters (including custom callables) require manual
        # review; do not assume they are unsafe without their bodies.
        if any(keyword.arg == "filter" for keyword in node.keywords):
            return None
        archive = func.value.id
        preceding = (
            self.text[:node.col_offset] if node.lineno == 1
            else "\n".join(self.text.split("\n")[:node.lineno - 1])
        )
        if re.search(rf"\b{re.escape(archive)}\s*\.\s*extraction_filter\s*=", preceding):
            return None
        return archive

    def _extraction_finding(self, node: ast.Call, archive: str) -> Finding:
        origin, snippet = self.archives[archive]
        definition = rule("PY-TAR-EXTRACT-001")
        sink = self._location(node)
        evidence = (ast.get_source_segment(self.text, node) or ast.unparse(node))[:350]
        return Finding(
            rule_id=definition.rule_id,
            name=definition.name,
            cwe=definition.cwe,
            severity=definition.severity,
            confidence=Confidence.MEDIUM,
            category=definition.category,
            language="Python",
            location=sink,
            source=origin,
            sink="tarfile." + node.func.attr,
            evidence=evidence,
            reason=definition.explanation,
            flow=[
                FlowStep("SOURCE", origin, snippet, "HTTP upload used as TAR archive input."),
                FlowStep("SINK", sink, evidence, "Uploaded TAR is extracted without an explicit filter."),
            ],
            remediations=remediations_for(definition.rule_id, evidence),
        )

    def visit_Call(self, node: ast.Call) -> None:
        archive = self._unfiltered_archive(node)
        if archive is not None:
            self.findings.append(self._extraction_finding(node, archive))
        self.generic_visit(node)


def _tarfile_imports(node: ast.stmt) -> dict[str, str]:
    if isinstance(node, ast.Import):
        return {alias.asname or alias.name: "tarfile" for alias in node.names if alias.name == "tarfile"}
    if isinstance(node, ast.ImportFrom) and node.module == "tarfile":
        return {alias.asname or alias.name: "tarfile." + alias.name for alias in node.names}
    return {}


def analyze_tar_extraction(relative: str, text: str) -> list[Finding]:
    try:
        tree = ast.parse(text, filename=relative)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return []
    imports: dict[str, str] = {}
    for node in tree.body:
        imports.update(_tarfile_imports(node))
    walker = _TarWalker(relative, text, imports)
    walker.visit(tree)
    return walker.findings
