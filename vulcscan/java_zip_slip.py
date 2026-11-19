"""Conservative Java ZIP entry to filesystem write path audit.

Only direct ZipEntry names, local File construction, and nearby writes are
tracked. Comments and literals are masked; target code is never executed.
"""
from __future__ import annotations

import re

from .models import Confidence, Finding, FlowStep, Location
from .rules import remediations_for, rule
from .source import C_STYLE, code_mask

_ENTRY = re.compile(
    r"\bZipEntry\s+(?P<name>[A-Za-z_]\w*)\s*=\s*"
    r"(?:[A-Za-z_]\w*\s*\.\s*)?(?:getNextEntry|nextElement|getEntry)\s*\("
)
_FILE = re.compile(
    r"\b(?:File\s+)?(?P<dest>[A-Za-z_]\w*)\s*=\s*new\s+File\s*\(\s*"
    r"(?P<root>[A-Za-z_]\w*)\s*,\s*"
    r"(?P<entry>[A-Za-z_]\w*)\s*\.\s*getName\s*\(\s*\)\s*\)"
)
_WRITE = re.compile(
    r"\bnew\s+FileOutputStream\s*\(\s*(?P<name>[A-Za-z_]\w*)\s*\)"
    r"|\bFiles\s*\.\s*copy\s*\(\s*[^;\n]{1,160}?,\s*(?P<copy>[A-Za-z_]\w*)\s*\.\s*toPath\s*\(\s*\)"
)
_GUARD = re.compile(
    r"\b(?:getCanonicalPath|toRealPath|normalize)\s*\("
    r"[\s\S]{0,450}?\bstartsWith\s*\("
    r"|\bstartsWith\s*\([\s\S]{0,450}?\b(?:getCanonicalPath|toRealPath|normalize)\s*\("
)


def analyze_java_zip_slip(path: str, source: str) -> list[Finding]:
    visible = code_mask(source, C_STYLE)
    definition = rule("JAVA-ZIPSLIP-001")
    findings: list[Finding] = []

    def location(start: int, end: int) -> Location:
        return Location(
            path, source.count("\n", 0, start) + 1,
            start - source.rfind("\n", 0, start),
            source.count("\n", 0, end) + 1,
        )

    for candidate in _FILE.finditer(visible):
        previous = visible[max(0, candidate.start() - 1600):candidate.start()]
        entry_name = candidate.group("entry")
        recognized = [
            match for match in _ENTRY.finditer(previous)
            if match.group("name") == entry_name
        ]
        if not recognized:
            continue
        after = visible[candidate.end():candidate.end() + 1700]
        for sink in _WRITE.finditer(after):
            target = sink.group("name") or sink.group("copy")
            if target != candidate.group("dest"):
                continue
            between = visible[candidate.end():candidate.end() + sink.start()]
            # Do not claim a vulnerability when a recognizable containment
            # guard appears, even if its correctness needs separate review.
            if _GUARD.search(between):
                continue
            origin_start = candidate.start("entry")
            origin_end = candidate.end("entry")
            sink_start = candidate.end() + sink.start()
            sink_end = candidate.end() + sink.end()
            evidence = " ".join(source[candidate.start():sink_end].split())[:350]
            source_location = location(origin_start, origin_end)
            sink_location = location(sink_start, sink_end)
            findings.append(Finding(
                rule_id=definition.rule_id, name=definition.name,
                cwe=definition.cwe, severity=definition.severity,
                confidence=Confidence.MEDIUM, category=definition.category,
                language="Java", location=sink_location,
                source=source_location, sink="ZIP entry to output file",
                evidence=evidence, reason=definition.explanation,
                flow=[
                    FlowStep("SOURCE", source_location, entry_name + ".getName()",
                             "Path comes from a ZIP entry name."),
                    FlowStep("SINK", sink_location, source[sink_start:sink_end],
                             "An unvalidated archive entry path is opened for writing."),
                ],
                remediations=remediations_for(definition.rule_id, evidence),
            ))
            break
    return findings
