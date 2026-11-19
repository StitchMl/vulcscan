"""Bounded Go archive/zip entry-path extraction audit.

Only a direct range over Zip reader .File entries, filepath.Join(entry.Name),
and subsequent os.Create / os.OpenFile on the same local path are recognized.
No Go code or archives are executed or opened.
"""
from __future__ import annotations

import re

from .models import Confidence, Finding, FlowStep, Location
from .rules import remediations_for, rule
from .source import C_STYLE, blank_comments, code_mask

_LOOP = re.compile(
    r"\bfor\s+_,\s*(?P<item>[A-Za-z_]\w*)\s*:=\s*range\s+"
    r"[A-Za-z_]\w*\s*\.\s*File\s*\{"
)
_JOIN = re.compile(
    r"\b(?P<dest>[A-Za-z_]\w*)\s*:=\s*filepath\s*\.\s*Join\s*\(\s*"
    r"(?P<root>[A-Za-z_]\w*)\s*,\s*"
    r"(?P<entry>[A-Za-z_]\w*)\s*\.\s*Name\s*\)"
)
_WRITE = re.compile(
    r"\bos\s*\.\s*(?:Create|OpenFile)\s*\(\s*(?P<dest>[A-Za-z_]\w*)\s*[,)]"
)
_GUARD = re.compile(
    r"\bfilepath\s*\.\s*Rel\s*\("
    r"[\s\S]{0,500}?\b(?:strings\s*\.\s*HasPrefix|filepath\s*\.\s*IsAbs)\s*\("
)


def _block_end(mask: str, brace: int) -> int | None:
    depth = 0
    for at in range(brace, len(mask)):
        if mask[at] == "{":
            depth += 1
        elif mask[at] == "}":
            depth -= 1
            if depth == 0:
                return at
    return None


def analyze_go_zip_slip(path: str, source: str) -> list[Finding]:
    visible = blank_comments(source, C_STYLE)
    mask = code_mask(source, C_STYLE)
    if not re.search(r"""["']archive/zip["']""", visible):
        return []
    definition = rule("GO-ZIPSLIP-001")
    findings: list[Finding] = []

    def loc(start: int, end: int) -> Location:
        return Location(
            path,
            source.count("\n", 0, start) + 1,
            start - source.rfind("\n", 0, start),
            source.count("\n", 0, end) + 1,
        )

    for loop in _LOOP.finditer(mask):
        closing = _block_end(mask, loop.end() - 1)
        if closing is None:
            continue
        body = mask[loop.end():closing]
        source_body = visible[loop.end():closing]
        for join in _JOIN.finditer(body):
            if join.group("entry") != loop.group("item"):
                continue
            following = body[join.end():]
            for write in _WRITE.finditer(following):
                if write.group("dest") != join.group("dest"):
                    continue
                safe_section = source_body[join.end():join.end() + write.start()]
                if _GUARD.search(safe_section):
                    continue
                source_start = loop.end() + join.start("entry")
                source_end = loop.end() + join.end("entry") + len(".Name")
                sink_start = loop.end() + join.end() + write.start()
                sink_end = loop.end() + join.end() + write.end()
                src_loc, dst_loc = loc(source_start, source_end), loc(sink_start, sink_end)
                evidence = " ".join(source[loop.end() + join.start():sink_end].split())[:350]
                findings.append(Finding(
                    rule_id=definition.rule_id, name=definition.name,
                    cwe=definition.cwe, severity=definition.severity,
                    confidence=Confidence.MEDIUM, category=definition.category,
                    language="Go", location=dst_loc, source=src_loc,
                    sink="ZIP entry to os file write", evidence=evidence,
                    reason=definition.explanation,
                    flow=[
                        FlowStep("SOURCE", src_loc, source[source_start:source_end],
                                 "ZIP archive member name."),
                        FlowStep("SINK", dst_loc, source[sink_start:sink_end],
                                 "Archive-derived path opened for writing."),
                    ],
                    remediations=remediations_for(definition.rule_id, evidence),
                ))
                break
    return findings
