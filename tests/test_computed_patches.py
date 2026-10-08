from __future__ import annotations

import pytest

from vulcscan.guidance import enrich_finding
from vulcscan.models import Confidence, Finding, FlowStep, Location, Severity
from vulcscan.scanner import scan_path


def _finding(language: str, family: str, evidence: str, sink: str, source: str, propagation: str = "") -> Finding:
    location = Location("service.test", 9, 1)
    flow = [FlowStep("SOURCE", Location("service.test", 4, 1), source, "Remote input.")]
    if propagation:
        flow.append(FlowStep("PROPAGATION", Location("service.test", 6, 1), propagation, "Assigned."))
    flow.append(FlowStep("SINK", location, evidence, f"Value reaches {sink}."))
    prefix = {"JavaScript": "JS", "PHP": "PHP", "Java": "JAVA", "C#": "CS", "Go": "GO", "Ruby": "RB"}[language]
    return Finding(
        rule_id=f"{prefix}-{family}-001",
        name="test",
        cwe="CWE-1",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category=family,
        language=language,
        location=location,
        sink=sink,
        evidence=evidence,
        reason="test",
        source=flow[0].location,
        flow=flow,
    )


@pytest.mark.parametrize(
    ("finding", "required"),
    [
        (
            _finding("JavaScript", "CMD", "exec('convert ' + imageName)", "child_process.exec", "req.query.image", "const imageName = req.query.image"),
            ('execFile("convert"', "imageName"),
        ),
        (
            _finding("PHP", "XSS", "echo $displayName", "PHP output", "$_GET['name']", "$displayName = $_GET['name']"),
            ("htmlspecialchars($displayName", "ENT_SUBSTITUTE"),
        ),
        (
            _finding("Java", "PATH", 'Files.readString(Path.of("/srv/reports/" + reportName))', "java.nio.file.Files", 'request.getParameter("report")', 'String reportName = request.getParameter("report")'),
            ('Path.of("/srv/reports/")', "base.resolve(reportName)"),
        ),
        (
            _finding("Go", "SSRF", 'http.NewRequestWithContext(ctx, "GET", targetURL, nil)', "http.NewRequestWithContext", 'r.URL.Query().Get("url")', 'targetURL := r.URL.Query().Get("url")'),
            ("url.Parse(targetURL)", "allowedHosts[target.Hostname()]"),
        ),
        (
            _finding("C#", "DESER", "formatter.Deserialize(requestBody)", "native .NET deserialization", "Request.Body", "var requestBody = ReadBody(Request.Body)"),
            ("JsonSerializer.Deserialize<RequestDto>(requestBody)", "fixed schema"),
        ),
        (
            _finding("Ruby", "CODE", "eval(expression)", "eval", "params[:expression]", "expression = params[:expression]"),
            ("JSON.parse(expression)", "fixed functions"),
        ),
    ],
)
def test_patch_uses_recovered_sink_and_value(finding: Finding, required: tuple[str, str]) -> None:
    enrich_finding(finding)

    patch = finding.remediations[0]
    combined = f"{patch.guidance}\n{patch.suggested}"
    assert required[0] in combined
    assert required[1] in combined
    assert finding.sink in patch.guidance
    assert patch.current == finding.evidence
    assert patch.machine_applicable is False


def test_unknown_path_base_uses_explicit_policy_placeholder() -> None:
    finding = _finding(
        "JavaScript",
        "PATH",
        "fs.readFile(fileName)",
        "fs.readFile",
        "req.query.file",
        "const fileName = req.query.file",
    )

    enrich_finding(finding)

    patch = finding.remediations[0]
    assert "ALLOWED_BASE" in (patch.suggested or "")
    assert "fileName" in (patch.suggested or "")
    assert patch.machine_applicable is False


def test_php_command_patch_splits_fixed_arguments_from_input() -> None:
    finding = _finding(
        "PHP",
        "CMD",
        "shell_exec('ping -c 1 ' . $host)",
        "PHP command execution",
        "$_GET['host']",
        "$host = $_GET['host']",
    )

    enrich_finding(finding)

    patch = finding.remediations[0]
    assert 'new Process(["ping", "-c", "1", $host])' in (patch.suggested or "")
    assert "ALLOWED_PROGRAM" not in (patch.suggested or "")


def test_php_xss_patch_preserves_markup_and_encodes_only_unsafe_values() -> None:
    finding = _finding(
        "PHP",
        "XSS",
        'echo "<strong>" . htmlspecialchars($author) . "</strong>" . $comment;',
        "PHP echo",
        "$_GET['comment']",
    )

    enrich_finding(finding)

    patch = finding.remediations[0]
    assert "htmlspecialchars($author)" in (patch.suggested or "")
    assert "htmlspecialchars($comment, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')" in (patch.suggested or "")
    assert '"<strong>"' in (patch.suggested or "")


def test_scanner_computes_command_patch_from_real_flow(tmp_path) -> None:
    (tmp_path / "convert.js").write_text(
        "const cp = require('child_process');\n"
        "app.get('/convert', (req, res) => {\n"
        "  const imageName = req.query.image;\n"
        "  cp.exec('convert ' + imageName);\n"
        "});\n",
        encoding="utf-8",
    )

    finding = next(
        item for item in scan_path(tmp_path, cve=False).findings if item.rule_id == "JS-CMD-001"
    )
    patch = next(item for item in finding.remediations if item.preferred)

    assert 'execFile("convert", ["--", imageName]' in (patch.suggested or "")
    assert "child_process.exec" in patch.guidance
    assert patch.machine_applicable is False


@pytest.mark.parametrize(
    ("rule_id", "language", "sink", "evidence", "required"),
    [
        ("PHP-URL-INCLUDE-001", "Configuration", "allow_url_include", "allow_url_include = On", "Off"),
        ("DEBUG-001", "Configuration", "display_errors", "display_errors = On", "display_errors = Off"),
        ("DOCKER-ROOT-001", "Dockerfile", "container user", "FROM ubuntu:22.04", "USER 10001:10001"),
        ("SECRET-001", "Environment", "WAREHOUSE_API_KEY", "WAREHOUSE_API_KEY=<redacted>", "WAREHOUSE_API_KEY"),
        ("CSRF-001", "PHP", "state-changing request", "move_uploaded_file($tmp, $dest)", "hash_equals"),
        ("DB-RACE-001", "PHP", "database UPDATE", "UPDATE coupon SET remaining = remaining - 1 WHERE code = ?", "remaining > 0"),
        ("SESSION-FIXATION-001", "PHP", "session state", "$_SESSION['admin'] = true;", "session_regenerate_id"),
        ("UPLOAD-MIME-001", "PHP", "move_uploaded_file", "move_uploaded_file($_FILES['image']['tmp_name'], $dest);", "finfo"),
        ("WEAK-HASH-001", "SQL", "SQL MD5 password hash", "('user', MD5('test'))", "argon2id"),
        ("CLEARTEXT-PASSWORD-001", "SQL", "SQL seed password", "INSERT INTO users VALUES ('u', '<redacted>')", "argon2id"),
    ],
)
def test_rule_specific_findings_receive_concrete_review_patch(
    rule_id: str,
    language: str,
    sink: str,
    evidence: str,
    required: str,
) -> None:
    location = Location("service.test", 7, 1)
    finding = Finding(
        rule_id=rule_id,
        name="test",
        cwe="CWE-1",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category="test",
        language=language,
        location=location,
        sink=sink,
        evidence=evidence,
        reason="test",
    )

    enrich_finding(finding)

    patch = next(item for item in finding.remediations if item.preferred)
    assert required in (patch.suggested or "")
    assert patch.current == evidence
    assert patch.machine_applicable is False
