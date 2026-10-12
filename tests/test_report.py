from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from vulcscan import cli
from vulcscan.models import (
    Confidence,
    Dependency,
    Finding,
    FlowStep,
    Location,
    Remediation,
    ScanError,
    ScanResult,
    Severity,
    Vulnerability,
)
from vulcscan.report import (
    filter_findings,
    render_json,
    render_text,
    render_unified_diff,
    write_report,
)


def _finding(
    severity: Severity,
    line: int,
    *,
    file: str = "src/app.py",
    current: str | None = None,
    suggested: str | None = None,
    machine_applicable: bool = False,
) -> Finding:
    location = Location(file=file, line=line, column=4, function="handler")
    remediation = Remediation(
        title="Avoid shell parsing",
        guidance="Pass an argument list with shell disabled.",
        preferred=True,
        patch_confidence=Confidence.HIGH,
        patch_risk="LOW",
        current=current,
        suggested=suggested,
        machine_applicable=machine_applicable,
    )
    return Finding(
        rule_id=f"PY-CMD-{line}",
        name="OS Command Injection",
        cwe="CWE-78",
        severity=severity,
        confidence=Confidence.HIGH,
        category="COMMAND_EXECUTION",
        language="Python",
        location=location,
        source=Location(file="src/routes.py", line=3, column=8, function="route"),
        flow=[
            FlowStep(
                kind="source",
                location=Location(file="src/routes.py", line=3),
                code='command = request.args["command"]',
                description="HTTP query parameter",
            ),
            FlowStep(
                kind="sink",
                location=location,
                code="subprocess.run(command, shell=True)",
                description="shell execution",
            ),
        ],
        sink="subprocess.run(..., shell=True)",
        evidence="Tainted command reaches a shell.",
        reason="User input reaches shell execution without a recognized sanitizer.",
        remediations=[remediation],
    )


def _result(findings: list[Finding]) -> ScanResult:
    return ScanResult(
        metadata={
            "root": "/srv/example",
            "platform": "Linux",
            "files_discovered": 9,
            "files_analyzed": 7,
            "files_skipped": 2,
            "languages": ["Python", "JavaScript"],
            "duration_seconds": 0.125,
            "offline": True,
        },
        findings=findings,
        dependencies=[
            Dependency(
                name="example-lib",
                version="1.0.0",
                ecosystem="PyPI",
                source_file="requirements.txt",
                line=2,
                resolved=True,
            )
        ],
        dependency_vulnerabilities=[
            Vulnerability(
                id="CVE-2026-0001",
                package="example-lib",
                installed_version="1.0.0",
                ecosystem="PyPI",
                summary="Example advisory",
                severity="HIGH",
                affected_ranges=(">=1,<1.0.1",),
                fixed_versions=("1.0.1",),
                source_file="requirements.txt",
                source_line=2,
            )
        ],
        errors=[ScanError(file="broken.py", phase="parse", message="invalid syntax")],
    )


def test_json_schema_is_flat_stable_and_sorted() -> None:
    result = _result(
        [_finding(Severity.MEDIUM, 20), _finding(Severity.CRITICAL, 40)]
    )

    first = render_json(result)
    second = render_json(result)
    payload = json.loads(first)

    assert first == second
    assert list(payload) == [
        "metadata",
        "findings",
        "dependencies",
        "dependency_vulnerabilities",
        "errors",
    ]
    assert [item["severity"] for item in payload["findings"]] == [
        "CRITICAL",
        "MEDIUM",
    ]
    assert payload["findings"][0]["file"] == "src/app.py"
    assert payload["findings"][0]["line"] == 40
    assert "location" not in payload["findings"][0]
    assert payload["metadata"]["severity_counts"] == {
        "critical": 1,
        "high": 0,
        "medium": 1,
        "low": 0,
        "info": 0,
    }


def test_severity_filter_uses_threshold() -> None:
    findings = [
        _finding(Severity.INFO, 1),
        _finding(Severity.HIGH, 2),
        _finding(Severity.CRITICAL, 3),
    ]

    filtered = filter_findings(findings, Severity.HIGH)

    assert [finding.severity for finding in filtered] == [
        Severity.HIGH,
        Severity.CRITICAL,
    ]
    payload = json.loads(render_json(_result(findings), Severity.HIGH))
    assert [item["severity"] for item in payload["findings"]] == [
        "CRITICAL",
        "HIGH",
    ]


def test_text_report_contains_evidence_patch_and_summary() -> None:
    result = _result(
        [
            _finding(
                Severity.HIGH,
                8,
                file=r"src\app.py",
                current="subprocess.run(command, shell=True)",
                suggested="subprocess.run([program, command], check=True)",
            )
        ]
    )

    report = render_text(result, patch_preview=True)

    assert "F-001  HIGH     OS Command Injection  CWE-78" in report
    assert "Confidence HIGH  |  Rule PY-CMD-8" in report
    assert r"src\app.py:8 in handler()" in report
    assert "src/routes.py:3" in report
    assert "PRIORITY INDEX" in report
    assert "TRACE" in report
    assert "FIX" in report
    assert "CURRENT" in report
    assert "SUGGESTED" in report
    assert "Dependency vulnerabilities: 1" in report
    assert "[DEPENDENCY] [HIGH] CVE-2026-0001" in report
    assert "Network:       DISABLED" in report
    assert "SCAN WARNINGS (1)" in report


def test_text_report_hides_preview_without_flag() -> None:
    finding = _finding(
        Severity.HIGH,
        1,
        current="dangerous()",
        suggested="safe()",
    )

    report = render_text(_result([finding]), patch_preview=False)

    assert "CURRENT" not in report
    assert "SUGGESTED" not in report


def test_text_report_wraps_detail_lines_to_requested_width() -> None:
    finding = _finding(Severity.HIGH, 1)
    finding.reason = "Untrusted input " + "crosses several application layers " * 8
    finding.test_vectors = ["Database-read proof: " + "send a controlled marker " * 12]

    report = render_text(_result([finding]), width=88)

    assert max(len(line) for line in report.splitlines()) <= 88
    assert "  VERIFY  1 probes" in report
    assert "    1. Database-read proof" in report


def test_text_report_color_is_explicit_and_json_stays_plain() -> None:
    result = _result([_finding(Severity.HIGH, 1)])

    plain = render_text(result)
    colored = render_text(result, color=True)

    assert "\x1b[" not in plain
    assert "\x1b[31m" in colored
    assert "\x1b[" not in render_json(result)


def test_cli_accepts_color_mode() -> None:
    args = cli.build_parser().parse_args([".", "--color", "never"])

    assert args.color == "never"


def test_cli_shows_patch_preview_by_default() -> None:
    assert cli.build_parser().parse_args(["."]).patch_preview is True
    assert cli.build_parser().parse_args([".", "--no-patch-preview"]).patch_preview is False


def test_cli_network_is_opt_in() -> None:
    default = cli.build_parser().parse_args(["."])
    update = cli.build_parser().parse_args([".", "--update-cve"])

    assert default.update_cve is False
    assert update.update_cve is True


def test_cli_default_scan_is_offline(tmp_path: Path, monkeypatch) -> None:
    captured = {}

    def fake_scan(config):
        captured["config"] = config
        return _result([])

    monkeypatch.setattr(cli, "scan", fake_scan)
    assert cli.main([str(tmp_path)]) == 0
    assert captured["config"].offline is True


def test_cli_rejects_conflicting_network_flags(tmp_path: Path) -> None:
    assert cli.main([str(tmp_path), "--offline", "--update-cve"]) == 2


def test_cli_auto_color_enables_windows_terminal_support(monkeypatch) -> None:
    class Terminal:
        @staticmethod
        def isatty() -> bool:
            return True

    calls: list[bool] = []
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setattr(cli.sys, "stdout", Terminal())
    monkeypatch.setattr(cli, "_enable_windows_virtual_terminal", lambda: calls.append(True) or True)

    assert cli._use_color("auto", None, "text") is True
    assert calls == [True]
    assert cli._use_color("auto", Path("report.txt"), "text") is False
    assert cli._use_color("auto", None, "json") is False


def test_cli_explicit_color_overrides_no_color_environment(monkeypatch) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setattr(cli, "_enable_windows_virtual_terminal", lambda: True)

    assert cli._use_color("always", None, "text") is True
    assert cli._use_color("auto", None, "text") is False


def test_write_report_creates_parent_directories(tmp_path: Path) -> None:
    destination = tmp_path / "nested" / "report.json"

    write_report(destination, "{}\n")

    assert destination.read_text(encoding="utf-8") == "{}\n"


def test_unified_diff_is_verified_and_does_not_modify_source(tmp_path: Path) -> None:
    source = tmp_path / "src" / "app.py"
    source.parent.mkdir()
    original = "value = 1\nsubprocess.run(command, shell=True)\n"
    source.write_text(original, encoding="utf-8", newline="\n")
    finding = _finding(
        Severity.HIGH,
        2,
        current="subprocess.run(command, shell=True)",
        suggested="subprocess.run([program, command], check=True)",
        machine_applicable=True,
    )

    diff = render_unified_diff(_result([finding]), tmp_path)

    assert "--- a/src/app.py" in diff
    assert "+++ b/src/app.py" in diff
    assert "-subprocess.run(command, shell=True)" in diff
    assert "+subprocess.run([program, command], check=True)" in diff
    assert source.read_text(encoding="utf-8") == original


def test_unified_diff_skips_mismatch_and_path_escape(tmp_path: Path) -> None:
    source = tmp_path / "src" / "app.py"
    source.parent.mkdir()
    source.write_text("safe_call()\n", encoding="utf-8")
    mismatch = _finding(
        Severity.HIGH,
        1,
        current="dangerous_call()",
        suggested="safe_call()",
    )
    escaped = _finding(
        Severity.HIGH,
        1,
        file="../outside.py",
        current="dangerous_call()",
        suggested="safe_call()",
    )

    assert render_unified_diff(_result([mismatch, escaped]), tmp_path) == ""


def test_cli_options_and_json_output_are_cross_platform(
    tmp_path: Path,
    monkeypatch,
) -> None:
    target = tmp_path / "path with spaces"
    target.mkdir()
    output = tmp_path / "reports" / "scan.json"
    captured = {}

    def fake_scan(config):
        captured["config"] = config
        return _result([_finding(Severity.HIGH, 2)])

    monkeypatch.setattr(cli, "scan", fake_scan)

    status = cli.main(
        [
            str(target),
            "--offline",
            "--no-cve",
            "--output",
            str(output),
            "--severity",
            "high",
            "--exclude",
            "generated/*",
            "--max-file-size",
            "1.5MiB",
            "--patch-preview",
        ]
    )

    config = captured["config"]
    assert status == 0
    assert config.root == target.resolve()
    assert config.offline is True
    assert config.cve is False
    assert config.format == "json"
    assert config.min_severity is Severity.HIGH
    assert config.excludes == ("generated/*",)
    assert config.max_file_size == 1_572_864
    assert config.patch_preview is True
    assert json.loads(output.read_text(encoding="utf-8"))["findings"]


def test_cli_rejects_missing_directory(tmp_path: Path, capsys) -> None:
    status = cli.main([str(tmp_path / "missing"), "--offline"])

    assert status == 2
    assert "cannot access scan path" in capsys.readouterr().err


def test_cli_generates_verified_diff_without_changing_target(
    tmp_path: Path,
    monkeypatch,
) -> None:
    target = tmp_path / "target"
    source = target / "src" / "app.py"
    source.parent.mkdir(parents=True)
    original = "value = 1\nsubprocess.run(command, shell=True)\n"
    source.write_text(original, encoding="utf-8", newline="\n")
    finding = _finding(
        Severity.HIGH,
        2,
        current="subprocess.run(command, shell=True)",
        suggested="subprocess.run([program, command], check=True)",
        machine_applicable=True,
    )
    monkeypatch.setattr(cli, "scan", lambda config: _result([finding]))
    diff_path = tmp_path / "fixes.patch"

    status = cli.main(
        [
            str(target),
            "--offline",
            "--no-cve",
            "--generate-diff",
            str(diff_path),
        ]
    )

    assert status == 0
    assert "+subprocess.run([program, command], check=True)" in diff_path.read_text(
        encoding="utf-8"
    )
    assert source.read_text(encoding="utf-8") == original


def test_parse_size_rejects_zero_bytes() -> None:
    with pytest.raises(argparse.ArgumentTypeError, match="greater than zero"):
        cli.parse_size("0.1B")
