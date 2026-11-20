"""Focused safeguards for generated diffs and endpoint verification snippets."""
from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace

from vulcscan.attack_surface import map_attack_surface
from vulcscan.models import Confidence, Finding, FlowStep, Location, Remediation, ScanResult, Severity
from vulcscan.report import render_unified_diff
from vulcscan.scanner import scan_path


def _finding(line: int, *, current: str, suggested: str) -> Finding:
    location = Location(file="app.py", line=line, function="lookup")
    return Finding(
        rule_id=f"PY-TEST-{line}",
        name="test",
        cwe="CWE-78",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category="COMMAND_EXECUTION",
        language="Python",
        location=location,
        sink="run",
        evidence=current,
        reason="test",
        remediations=[
            Remediation(
                title="fix",
                guidance="test",
                preferred=True,
                patch_confidence=Confidence.HIGH,
                patch_risk="LOW",
                current=current,
                suggested=suggested,
                machine_applicable=True,
            )
        ],
    )


def test_invalid_python_fix_does_not_hide_independent_safe_fix(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("a = 1\nb = 2\n", encoding="utf-8")
    findings = [
        _finding(1, current="a = 1", suggested="a = ("),
        _finding(2, current="b = 2", suggested="b = 3"),
    ]
    diff = render_unified_diff(ScanResult(metadata={}, findings=findings), tmp_path)
    assert "+b = 3" in diff
    assert "+a = (" not in diff
    assert (tmp_path / "app.py").read_text(encoding="utf-8") == "a = 1\nb = 2\n"


def test_missing_import_fix_does_not_hide_safe_fix(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("a = 1\nb = 2\n", encoding="utf-8")
    findings = [
        _finding(1, current="a = 1", suggested="a = hmac.compare_digest(x, y)"),
        _finding(2, current="b = 2", suggested="b = 3"),
    ]
    diff = render_unified_diff(ScanResult(metadata={}, findings=findings), tmp_path)
    assert "+b = 3" in diff
    assert "hmac.compare_digest" not in diff


def _route_finding(code: str) -> Finding:
    location = Location("app.py", 4, function="lookup")
    return Finding(
        rule_id="PY-SQL-001",
        name="test",
        cwe="CWE-89",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category="SQL_EXECUTION",
        language="Python",
        location=location,
        sink="execute",
        evidence="execute(query)",
        reason="test",
        flow=[FlowStep("SOURCE", Location("app.py", 5), code, "HTTP query input")],
    )


def _routes(source: str, finding: Finding) -> list[dict]:
    file = SimpleNamespace(relative="app.py", language="Python", text=source)
    return map_attack_surface([file], [finding])


def test_get_query_source_has_localhost_canary_only() -> None:
    routes = _routes(
        "@app.get('/items')\ndef lookup():\n    value = request.args['item']\n    return value\n",
        _route_finding("value = request.args['item']"),
    )
    assert routes[0]["finding_rules"] == ["PY-SQL-001"]
    assert routes[0]["verify_curl"].startswith("curl --silent --show-error --max-time 5 ")
    assert "127.0.0.1:8000/items?item=VULCSCAN_CANARY" in routes[0]["verify_curl"]


def test_post_or_dynamic_path_does_not_generate_curl() -> None:
    finding = _route_finding("value = request.args.get('item')")
    for decorator in ("@app.post('/items')", "@app.get('/items/<item>')", "@app.get('/items/{item}')"):
        routes = _routes(decorator + "\ndef lookup():\n    return request.args.get('item')\n", finding)
        assert routes
        assert "verify_curl" not in routes[0]


def test_no_source_trace_does_not_generate_guess() -> None:
    routes = _routes("@app.get('/items')\ndef lookup():\n    return 'ok'\n", _route_finding("value = os.getenv('ITEM')"))
    assert routes
    assert "verify_curl" not in routes[0]


def test_real_yaml_fix_is_syntactic_and_clean_on_targeted_rescan(tmp_path: Path) -> None:
    """Validate a real scan-generated patch without executing target Python."""
    source = (
        "import yaml\n"
        "from flask import request\n"
        "def handler():\n"
        "    return yaml.load(request.args['payload'], Loader=yaml.Loader)\n"
    )
    target = tmp_path / "app.py"
    target.write_text(source, encoding="utf-8")
    before = scan_path(tmp_path, cve=False)
    findings = [f for f in before.findings if f.rule_id == "PY-DESER-001"]
    assert findings
    eligible = [
        remediation for finding in findings
        for remediation in finding.remediations if remediation.machine_applicable
    ]
    assert eligible
    patch = eligible[0]
    assert patch.current is not None and patch.suggested is not None

    diff = render_unified_diff(before, tmp_path)
    assert "+    return yaml.safe_load(request.args['payload'])" in diff
    assert target.read_text(encoding="utf-8") == source

    updated = source.replace(patch.current, patch.suggested, 1)
    ast.parse(updated)
    target.write_text(updated, encoding="utf-8")
    after = scan_path(tmp_path, cve=False, only_files=frozenset({"app.py"}))
    assert not [f for f in after.findings if f.rule_id == "PY-DESER-001"]
    assert after.metadata["files_analyzed"] == 1


