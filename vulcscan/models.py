from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(StrEnum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

CONFIDENCE_RANK = {
    Confidence.HIGH: 0,
    Confidence.MEDIUM: 1,
    Confidence.LOW: 2,
}


@dataclass(frozen=True, slots=True)
class Location:
    file: str
    line: int
    column: int | None = None
    end_line: int | None = None
    end_column: int | None = None
    function: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return _without_none(asdict(self))


@dataclass(frozen=True, slots=True)
class FlowStep:
    kind: str
    location: Location
    code: str
    description: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "location": self.location.as_dict(),
            "code": self.code,
            "description": self.description,
        }


@dataclass(frozen=True, slots=True)
class Remediation:
    title: str
    guidance: str
    preferred: bool
    patch_confidence: Confidence
    patch_risk: str
    current: str | None = None
    suggested: str | None = None
    machine_applicable: bool = False

    def as_dict(self) -> dict[str, Any]:
        return _without_none(
            {
                "title": self.title,
                "guidance": self.guidance,
                "preferred": self.preferred,
                "patch_confidence": self.patch_confidence.value,
                "patch_risk": self.patch_risk,
                "current": self.current,
                "suggested": self.suggested,
                "machine_applicable": self.machine_applicable,
            }
        )


@dataclass(slots=True)
class Finding:
    rule_id: str
    name: str
    cwe: str
    severity: Severity
    confidence: Confidence
    category: str
    language: str
    location: Location
    sink: str
    evidence: str
    reason: str
    source: Location | None = None
    flow: list[FlowStep] = field(default_factory=list)
    related_locations: list[Location] = field(default_factory=list)
    remediations: list[Remediation] = field(default_factory=list)
    test_vectors: list[str] = field(default_factory=list)
    tags: tuple[str, ...] = ()
    patch_location: Location | None = None

    def __post_init__(self) -> None:
        if self.patch_location is None:
            self.patch_location = self.location

    def dedup_key(self) -> tuple[str, int, str, str]:
        return (
            self.location.file.casefold(),
            self.location.line,
            self.cwe,
            self.sink,
        )

    def sort_key(self) -> tuple[int, int, str, int, str]:
        return (
            SEVERITY_RANK[self.severity],
            CONFIDENCE_RANK[self.confidence],
            self.location.file.casefold(),
            self.location.line,
            self.rule_id,
        )

    def as_dict(self) -> dict[str, Any]:
        cwe_number = self.cwe.removeprefix("CWE-")
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "cwe": self.cwe,
            "reference": f"https://cwe.mitre.org/data/definitions/{cwe_number}.html",
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "category": self.category,
            "language": self.language,
            "file": self.location.file,
            "line": self.location.line,
            "column": self.location.column,
            "end_line": self.location.end_line,
            "end_column": self.location.end_column,
            "function": self.location.function,
            "source": self.source.as_dict() if self.source else None,
            "flow": [step.as_dict() for step in self.flow],
            "sink": self.sink,
            "evidence": self.evidence,
            "reason": self.reason,
            "patch_location": (self.patch_location or self.location).as_dict(),
            "related_locations": [loc.as_dict() for loc in self.related_locations],
            "remediations": [item.as_dict() for item in self.remediations],
            "test_vectors": list(self.test_vectors),
            "patch_confidence": (
                self.remediations[0].patch_confidence.value if self.remediations else None
            ),
            "patch_risk": self.remediations[0].patch_risk if self.remediations else None,
            "tags": list(self.tags),
        }


@dataclass(frozen=True, slots=True)
class Dependency:
    name: str
    version: str | None
    ecosystem: str
    source_file: str
    line: int | None = None
    direct: bool = True
    resolved: bool = False
    constraint: str | None = None
    version_source: str | None = None  # "lockfile" or "manifest-pin" when resolved

    def key(self) -> tuple[str, str, str | None]:
        return (self.ecosystem.casefold(), self.name.casefold(), self.version)

    def as_dict(self) -> dict[str, Any]:
        return _without_none(asdict(self))


@dataclass(frozen=True, slots=True)
class Vulnerability:
    id: str
    package: str
    installed_version: str
    ecosystem: str
    summary: str
    severity: str
    aliases: tuple[str, ...] = ()
    affected_ranges: tuple[str, ...] = ()
    fixed_versions: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    source_file: str | None = None
    source_line: int | None = None
    cvss: float | None = None
    source: str = "OSV"
    fixed_version_note: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return _without_none(asdict(self))


@dataclass(frozen=True, slots=True)
class ScanError:
    file: str
    phase: str
    message: str

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(slots=True)
class ScanResult:
    metadata: dict[str, Any]
    findings: list[Finding] = field(default_factory=list)
    dependencies: list[Dependency] = field(default_factory=list)
    dependency_vulnerabilities: list[Vulnerability] = field(default_factory=list)
    errors: list[ScanError] = field(default_factory=list)

    def normalize(self) -> None:
        best: dict[tuple[str, int, str, str], Finding] = {}
        for finding in self.findings:
            key = finding.dedup_key()
            current = best.get(key)
            if current is None or finding.sort_key() < current.sort_key():
                best[key] = finding
        self.findings = sorted(best.values(), key=Finding.sort_key)
        self.dependencies = sorted(
            {item.key(): item for item in self.dependencies}.values(),
            key=lambda item: (
                item.ecosystem.casefold(),
                item.name.casefold(),
                item.version or "",
                item.source_file.casefold(),
            ),
        )
        self.dependency_vulnerabilities.sort(
            key=lambda item: (item.package.casefold(), item.id, item.installed_version)
        )
        self.errors.sort(key=lambda item: (item.file.casefold(), item.phase, item.message))

    def as_dict(self) -> dict[str, Any]:
        return {
            "metadata": self.metadata,
            "findings": [item.as_dict() for item in self.findings],
            "dependencies": [item.as_dict() for item in self.dependencies],
            "dependency_vulnerabilities": [
                item.as_dict() for item in self.dependency_vulnerabilities
            ],
            "errors": [item.as_dict() for item in self.errors],
        }


@dataclass(slots=True)
class ScanConfig:
    root: Path
    offline: bool = False
    cve: bool = True
    output: Path | None = None
    format: str = "text"
    min_severity: Severity = Severity.INFO
    excludes: tuple[str, ...] = ()
    max_file_size: int = 2 * 1024 * 1024
    patch_preview: bool = False
    generate_diff: Path | None = None
    cache_path: Path | None = None
    only_files: frozenset[str] | None = None  # repository-relative paths; None scans everything


def _without_none(data: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in data.items() if value is not None}
