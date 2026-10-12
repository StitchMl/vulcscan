"""Text, JSON and unified-diff rendering of scan results."""

from __future__ import annotations

import difflib
import json
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .models import (
    SEVERITY_RANK,
    Finding,
    Location,
    Remediation,
    ScanResult,
    Severity,
    Vulnerability,
)

_RULE = "=" * 66
_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
_DEPENDENCY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "UNKNOWN": 5}
_ANSI = {
    "reset": "\x1b[0m",
    "bold": "\x1b[1m",
    "dim": "\x1b[2m",
    "red": "\x1b[31m",
    "bright_red": "\x1b[91m",
    "yellow": "\x1b[33m",
    "blue": "\x1b[34m",
    "cyan": "\x1b[36m",
}
_SEVERITY_COLOR = {
    "CRITICAL": "bright_red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "blue",
    "INFO": "dim",
    "UNKNOWN": "dim",
}


def filter_findings(findings: Iterable[Finding], minimum: Severity | None = None) -> list[Finding]:
    items = list(findings)
    if minimum is None:
        return items
    return [item for item in items if SEVERITY_RANK[item.severity] <= SEVERITY_RANK[minimum]]


def _filter_vulnerabilities(items: Iterable[Vulnerability], minimum: Severity | None) -> list[Vulnerability]:
    values = list(items)
    if minimum is None or minimum is Severity.INFO:
        return values
    limit = SEVERITY_RANK[minimum]
    return [item for item in values if _DEPENDENCY_RANK.get(item.severity, 5) <= limit]


def _sorted_findings(result: ScanResult, minimum: Severity | None) -> list[Finding]:
    return sorted(filter_findings(result.findings, minimum), key=Finding.sort_key)


def _sorted_vulnerabilities(result: ScanResult, minimum: Severity | None) -> list[Vulnerability]:
    return sorted(
        _filter_vulnerabilities(result.dependency_vulnerabilities, minimum),
        key=lambda item: (_DEPENDENCY_RANK.get(item.severity, 5), item.package.casefold(), item.id),
    )


def report_data(result: ScanResult, minimum_severity: Severity | None = None) -> dict[str, Any]:
    """Build the stable, machine-readable report envelope."""
    findings = _sorted_findings(result, minimum_severity)
    vulnerabilities = _sorted_vulnerabilities(result, minimum_severity)
    metadata = dict(result.metadata)
    counts = Counter(item.severity.value for item in findings)
    metadata["severity_counts"] = {name.lower(): counts[name] for name in _SEVERITIES}
    metadata["finding_count"] = len(findings)
    metadata["dependency_count"] = len(result.dependencies)
    metadata["dependency_vulnerability_count"] = len(vulnerabilities)
    return {
        "metadata": metadata,
        "findings": [item.as_dict() for item in findings],
        "dependencies": [item.as_dict() for item in result.dependencies],
        "dependency_vulnerabilities": [item.as_dict() for item in vulnerabilities],
        "errors": [item.as_dict() for item in sorted(result.errors, key=lambda e: (e.file.casefold(), e.phase, e.message))],
    }


def render_json(result: ScanResult, minimum_severity: Severity | None = None, *, indent: int = 2) -> str:
    return json.dumps(report_data(result, minimum_severity), ensure_ascii=False, indent=indent) + "\n"


def _where(location: Location | None) -> str:
    if location is None:
        return ""
    text = f"{location.file}:{location.line}"
    return text + (f" in {location.function}()" if location.function else "")


def _paint(text: str, style: str, enabled: bool) -> str:
    return f"{_ANSI[style]}{text}{_ANSI['reset']}" if enabled else text


def _severity(value: str, enabled: bool) -> str:
    return _paint(value, _SEVERITY_COLOR.get(value, "dim"), enabled)


def _render_finding(number: int, finding: Finding, patch_preview: bool, color: bool) -> list[str]:
    lines = [
        f"{_paint(f'F-{number:03d}', 'bold', color)}  [{_severity(finding.severity.value, color)}] "
        f"{_paint(finding.name, 'bold', color)} ({finding.cwe})",
        f"      Location:   {_where(finding.location)}",
        f"      Severity:   {finding.severity.value}    Confidence: {finding.confidence.value}    Rule: {finding.rule_id}",
    ]
    sink_line = f"{finding.evidence[:100]}  @ {finding.location.file}:{finding.location.line}"
    if finding.source is not None:
        source_step = next((step for step in finding.flow if step.kind == "SOURCE"), None)
        code = source_step.code[:80] if source_step else ""
        lines.append(f"      Source:     {code}  @ {finding.source.file}:{finding.source.line}".rstrip())
        lines.append(f"      Sink:       {sink_line}")
        middle = [step for step in finding.flow if step.kind == "PROPAGATION"]
        if middle:
            lines.append("      Flow:       " + " -> ".join(f"line {step.location.line}" for step in middle[:6]) + " -> sink")
    else:
        lines.append(f"      Code:       {sink_line}")
    lines.append(f"      Why:        {finding.reason}")
    lines.append(f"      Reference:  https://cwe.mitre.org/data/definitions/{finding.cwe.removeprefix('CWE-')}.html")
    lines.append(f"      Patch at:   {_where(finding.patch_location)}")
    for location in finding.related_locations[:3]:
        lines.append(f"      Related:    {_where(location)}")
    for index, vector in enumerate(finding.test_vectors[:3], 1):
        label = "Test vector:" if index == 1 else "            "
        lines.append(f"      {label:<12} {vector}")
    preferred = next((item for item in finding.remediations if item.preferred), None)
    if preferred is not None:
        lines.append(f"      Fix:        {preferred.title}")
        lines.append(f"                  {preferred.guidance}")
        lines.append(f"                  Patch confidence: {preferred.patch_confidence.value}   Patch risk: {preferred.patch_risk}")
        if patch_preview and preferred.suggested:
            current = (preferred.current or "").replace("\n", "\n                  ")
            suggested = preferred.suggested.replace("\n", "\n                  ")
            lines.append(f"      Current:    {current}")
            lines.append(f"      Suggested:  {suggested}" + ("" if preferred.machine_applicable else "   (review before applying)"))
        if patch_preview:
            for alternative in [item for item in finding.remediations if not item.preferred][:2]:
                lines.append(f"      Alternative: {alternative.title}")
    lines.append("")
    return lines


def _render_vulnerability(number: int, item: Vulnerability, color: bool) -> list[str]:
    manifest = f"{item.source_file}:{item.source_line}" if item.source_file and item.source_line else (item.source_file or "")
    lines = [
        f"{_paint(f'D-{number:03d}', 'bold', color)}  [DEPENDENCY] [{_severity(item.severity, color)}] "
        f"{_paint(item.id, 'bold', color)}  {item.package} {item.installed_version} ({item.ecosystem})",
        f"      Manifest:   {manifest}",
        f"      Summary:    {item.summary[:160]}",
    ]
    if item.affected_ranges:
        lines.append(f"      Affected:   {'; '.join(item.affected_ranges[:4])}")
    if item.fixed_versions:
        lines.append(f"      Fixed in:   {', '.join(item.fixed_versions)}")
    else:
        lines.append("      Fixed in:   no fixed version published by the advisory")
    if item.fixed_version_note:
        lines.append(f"      Note:       {item.fixed_version_note}")
    if item.aliases:
        lines.append(f"      Aliases:    {', '.join(item.aliases[:4])}")
    reference = item.references[0] if item.references else f"https://osv.dev/vulnerability/{item.id}"
    lines.append(f"      Reference:  {reference}")
    lines.append("")
    return lines


def _counts_line(findings: list[Finding], color: bool = False) -> str:
    counts = Counter(item.severity.value for item in findings)
    return " | ".join(
        _severity(f"{counts[name]} {name.lower()}", color)
        for name in _SEVERITIES
        if counts[name]
    ) or "none"


def render_text(
    result: ScanResult,
    minimum_severity: Severity | None = None,
    *,
    patch_preview: bool = False,
    color: bool = False,
) -> str:
    findings = _sorted_findings(result, minimum_severity)
    vulnerabilities = _sorted_vulnerabilities(result, minimum_severity)
    metadata = result.metadata
    duration = metadata.get("scan_duration")
    duration_text = f"{duration:.2f}s" if isinstance(duration, (int, float)) else "unknown"
    high_confidence = sum(item.confidence.value == "HIGH" for item in findings)
    lines = [
        _paint("VulcScan - scan completed", "bold", color),
        f"Target:        {metadata.get('root', '')}",
        f"Files:         {metadata.get('files_analyzed', 0)} scanned, {metadata.get('files_skipped', 0)} skipped, {duration_text}",
        f"Network:       {metadata.get('network_access', 'DISABLED')}",
        f"Findings:      {len(findings)}  ({_counts_line(findings, color)})",
        f"High confidence: {high_confidence}",
        f"Dependency vulnerabilities: {len(vulnerabilities)}",
        "",
    ]
    if findings:
        lines.extend((
            _paint("CODE FINDINGS (most severe and most certain first)", "cyan", color),
            "Test vectors are for authorized, isolated systems. Prefer disposable data.",
            "-" * 66,
        ))
        for number, finding in enumerate(findings, 1):
            lines.extend(_render_finding(number, finding, patch_preview, color))
    if vulnerabilities:
        lines.extend((_paint("DEPENDENCY VULNERABILITIES", "cyan", color), "-" * 66))
        for number, item in enumerate(vulnerabilities, 1):
            lines.extend(_render_vulnerability(number, item, color))
    if result.errors:
        errors = sorted(result.errors, key=lambda e: (e.file.casefold(), e.phase, e.message))
        lines.extend((_paint(f"SCAN WARNINGS ({len(errors)}) - not vulnerabilities; these files were not fully analyzed", "yellow", color), "-" * 66))
        for error in errors[:10]:
            prefix = f"{error.file}: " if error.file else ""
            lines.append(f"  - {prefix}{error.phase}: {error.message[:160]}")
        if len(errors) > 10:
            lines.append(f"  - ... {len(errors) - 10} more (see --format json)")
        lines.append("")
    lines.append("-" * 66)
    if findings or vulnerabilities:
        lines.append(f"Scan complete: {len(findings)} findings ({_counts_line(findings, color)}), {high_confidence} high-confidence")
        lines.append(f"{len(vulnerabilities)} vulnerable dependency versions, {metadata.get('files_analyzed', 0)} files scanned in {duration_text}")
        lines.append("Priority: review CRITICAL/HIGH findings with HIGH confidence first.")
    else:
        lines.append("No findings detected by the enabled VulcScan rules.")
        lines.append(f"{metadata.get('files_analyzed', 0)} files scanned, {len(result.errors)} scan warnings.")
        lines.append("This is not proof that the code is secure: static rules cover known patterns only.")
    return "\n".join(lines).rstrip() + "\n"


def write_report(path: Path | str, content: str) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(content, encoding="utf-8", newline="\n")


def _safe_patch_path(root: Path, file_name: str) -> tuple[Path, str] | None:
    if not file_name:
        return None
    raw = Path(file_name)
    candidate = raw.resolve() if raw.is_absolute() else (root / raw).resolve()
    try:
        relative = candidate.relative_to(root)
    except ValueError:
        return None
    if not candidate.is_file():
        return None
    return candidate, relative.as_posix()


def _apply_edits(text: str, edits: list[tuple[int, int, str, str]]) -> str:
    """Apply single-region replacements whose current text matches exactly once."""
    lines = text.splitlines(keepends=True)
    occupied: set[int] = set()
    planned: list[tuple[int, int, str]] = []
    for start_line, end_line, current, replacement in edits:
        if start_line < 1 or end_line < start_line or end_line > len(lines):
            continue
        indices = range(start_line - 1, end_line)
        if any(index in occupied for index in indices):
            continue
        region = "".join(lines[start_line - 1 : end_line])
        if not current or region.count(current) != 1:
            continue
        occupied.update(indices)
        planned.append((start_line - 1, end_line, region.replace(current, replacement, 1)))
    for start, stop, replacement in sorted(planned, reverse=True):
        lines[start:stop] = replacement.splitlines(keepends=True)
    return "".join(lines)


def render_unified_diff(result: ScanResult, root: Path | str, minimum_severity: Severity | None = None) -> str:
    """Build a unified diff of machine-applicable fixes without touching files.

    A fix is used only when its ``current`` text occurs exactly once in the
    lines of the patch location; anything else is skipped.
    """
    root_path = Path(root).resolve()
    grouped: dict[tuple[Path, str], list[tuple[int, int, str, str]]] = {}
    for finding in _sorted_findings(result, minimum_severity):
        remediation = next((item for item in finding.remediations if item.machine_applicable and item.current and item.suggested is not None), None)
        if remediation is None:
            continue
        location = finding.patch_location or finding.location
        target = _safe_patch_path(root_path, location.file)
        if target is None:
            continue
        grouped.setdefault(target, []).append(
            (location.line, location.end_line or location.line, remediation.current or "", remediation.suggested or "")
        )
    chunks: list[str] = []
    for (path, relative), edits in sorted(grouped.items(), key=lambda pair: pair[0][1]):
        try:
            data = path.read_bytes()
            original = data.decode("utf-8-sig") if not data.startswith(b"\xef\xbb\xbf") else data[3:].decode("utf-8")
        except (OSError, UnicodeError):
            continue
        patched = _apply_edits(original, edits)
        if patched == original:
            continue
        chunks.extend(
            difflib.unified_diff(
                original.splitlines(keepends=True),
                patched.splitlines(keepends=True),
                fromfile=f"a/{relative}",
                tofile=f"b/{relative}",
            )
        )
    diff = "".join(chunks)
    if diff and not diff.endswith("\n"):
        diff += "\n\\ No newline at end of file\n"
    return diff
