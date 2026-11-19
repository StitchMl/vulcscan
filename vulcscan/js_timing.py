"""Conservative JavaScript/TypeScript secret equality timing audit.

Only direct HTTP fields compared to secret-named local identifiers are
recognized. The input is tokenized using existing code masking; no target
JavaScript is imported, evaluated or executed.
"""
from __future__ import annotations

import re

from .models import Confidence, Finding, FlowStep, Location
from .rules import remediations_for, rule
from .source import JS_STYLE, code_mask

_IDENTIFIER = r"[A-Za-z_$][\w$]*"
_REMOTE = rf"(?:req|request)\s*\.\s*(?:body|query|params|headers|cookies)\s*\.\s*{_IDENTIFIER}"
_OPERAND = rf"(?:{_REMOTE}|{_IDENTIFIER})"
_COMPARISON = re.compile(
    rf"(?<![\w$.])(?P<left>{_OPERAND})\s*"
    rf"(?P<operator>===|!==|==|!=)\s*(?P<right>{_OPERAND})(?!=)"
)
_REMOTE_ONLY = re.compile(rf"^{_REMOTE}$")
_SECRET_NAME = re.compile(r"(?i)(?:token|secret|hmac|signature|digest|api_?key|password_?hash|auth_?hash)")


def analyze_javascript_timing(path: str, source: str, language: str) -> list[Finding]:
    if language not in {"JavaScript", "TypeScript"}:
        return []
    visible = code_mask(source, JS_STYLE)
    definition = rule("JS-TIMING-001")
    findings: list[Finding] = []

    def location(start: int, end: int) -> Location:
        line = source.count("\n", 0, start) + 1
        column = start - source.rfind("\n", 0, start)
        end_line = source.count("\n", 0, end) + 1
        end_column = end - source.rfind("\n", 0, end)
        return Location(path, line, column, end_line, end_column)

    for match in _COMPARISON.finditer(visible):
        lhs, rhs = match.group("left"), match.group("right")
        left_http = _REMOTE_ONLY.fullmatch(lhs) is not None
        right_http = _REMOTE_ONLY.fullmatch(rhs) is not None
        if left_http == right_http:
            continue
        secret = rhs if left_http else lhs
        if not _SECRET_NAME.search(secret):
            continue
        if _REMOTE_ONLY.fullmatch(secret):
            continue
        source_part = "left" if left_http else "right"
        origin = location(match.start(source_part), match.end(source_part))
        sink_location = location(match.start(), match.end())
        evidence = " ".join(source[match.start():match.end()].split())[:350]
        findings.append(Finding(
            rule_id=definition.rule_id,
            name=definition.name,
            cwe=definition.cwe,
            severity=definition.severity,
            confidence=Confidence.MEDIUM,
            category=definition.category,
            language=language,
            location=sink_location,
            sink="secret equality comparison",
            evidence=evidence,
            reason=definition.explanation,
            source=origin,
            flow=[
                FlowStep("SOURCE", origin, " ".join(source[match.start(source_part):match.end(source_part)].split()),
                         "Direct HTTP request field."),
                FlowStep("SINK", sink_location, evidence,
                         "HTTP field compared to secret with JavaScript equality."),
            ],
            remediations=remediations_for(definition.rule_id, evidence),
        ))
    return findings
