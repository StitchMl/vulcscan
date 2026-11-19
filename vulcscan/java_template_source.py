"""Conservative Java HTTP-to-template-source analysis; target code is never run."""
from __future__ import annotations

import re

from .models import Confidence, Finding, FlowStep, Location
from .rules import remediations_for, rule
from .source import C_STYLE, blank_comments, code_mask

_REQUEST = r'(?:request|req)\s*\.\s*getParameter\s*\(\s*"[A-Za-z_][\w-]*"\s*\)'
_VALUE = rf'(?:{_REQUEST}|[A-Za-z_]\w*)'
_ASSIGNMENT = re.compile(
    rf'\b(?:String|var)\s+(?P<name>[A-Za-z_]\w*)\s*=\s*(?P<value>{_REQUEST})\s*;'
)
_READER = re.compile(rf'\bnew\s+StringReader\s*\(\s*(?P<value>{_VALUE})\s*\)')
_THYMELEAF = re.compile(
    rf'\b[A-Za-z_]\w*\s*\.\s*process\s*\(\s*(?P<value>{_VALUE})\s*,'
)
_TEMPLATE = re.compile(r'\bnew\s+Template\s*\(')
_RESOLVER = re.compile(r'\bnew\s+StringTemplateResolver\s*\(')


def analyze_java_template_source(path: str, source: str) -> list[Finding]:
    visible = blank_comments(source, C_STYLE)
    mask = code_mask(source, C_STYLE)
    definition = rule("JAVA-SSTI-001")
    result: list[Finding] = []

    def loc(position: int) -> Location:
        return Location(
            path, source.count("\n", 0, position) + 1,
            position - source.rfind("\n", 0, position),
        )

    def origin(value: str, offset: int) -> int | None:
        if re.fullmatch(_REQUEST, value):
            return offset
        if not re.fullmatch(r'[A-Za-z_]\w*', value):
            return None
        beginning = max(0, offset - 1500)
        previous = visible[beginning:offset]
        assignments = [
            match for match in _ASSIGNMENT.finditer(previous)
            if match.group("name") == value
        ]
        if not assignments:
            return None
        assignment = assignments[-1]
        if re.search(rf'\b{re.escape(value)}\s*=(?!=)', previous[assignment.end():]):
            return None
        return beginning + assignment.start("value")

    def emit(sink_start: int, source_start: int, label: str) -> None:
        src, dst = loc(source_start), loc(sink_start)
        evidence = source[sink_start:sink_start + 180].split("\n", 1)[0]
        result.append(Finding(
            rule_id=definition.rule_id, name=definition.name,
            cwe=definition.cwe, severity=definition.severity,
            confidence=Confidence.MEDIUM, category=definition.category,
            language="Java", location=dst, source=src, sink=label,
            evidence=evidence, reason=definition.explanation,
            flow=[
                FlowStep("SOURCE", src, "HTTP request parameter", "Untrusted template source."),
                FlowStep("SINK", dst, evidence, "Compiles request content as a template."),
            ],
            remediations=remediations_for(definition.rule_id, evidence),
        ))

    for reader in _READER.finditer(visible):
        if mask[reader.start():reader.start() + 3] != "new":
            continue
        from_http = origin(reader.group("value"), reader.start("value"))
        if from_http is None:
            continue
        # FreeMarker Template constructor directly accepts the StringReader.
        prefix = visible[max(0, reader.start() - 200):reader.start()]
        if _TEMPLATE.search(prefix):
            emit(reader.start(), from_http, "FreeMarker StringReader template source")

    if _RESOLVER.search(mask):
        for call in _THYMELEAF.finditer(visible):
            if mask[call.start()].isspace():
                continue
            from_http = origin(call.group("value"), call.start("value"))
            if from_http is not None:
                emit(call.start(), from_http, "Thymeleaf string template source")
    return result
