from __future__ import annotations

from pathlib import Path

from vulcscan.attack_surface import map_attack_surface
from vulcscan.cli import build_parser
from vulcscan.models import Confidence, Finding, FlowStep, Location, Severity
from vulcscan.remote import has_remote_source
from vulcscan.scanner import scan_path


def _finding(description: str, code: str) -> Finding:
    location = Location("app.py", 4)
    return Finding(
        rule_id="PY-SQL-001",
        name="SQL injection",
        cwe="CWE-89",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category="SQL_EXECUTION",
        language="Python",
        location=location,
        sink="execute",
        evidence="execute(query)",
        reason="Untrusted SQL",
        flow=[FlowStep("SOURCE", location, code, description)],
    )


def test_remote_classification_requires_explicit_source() -> None:
    assert has_remote_source(_finding("HTTP query parameter", "request.args['id']"))
    assert has_remote_source(_finding("Untrusted input", "$_POST['id']"))
    assert not has_remote_source(_finding("Command-line argument", "sys.argv[1]"))
    assert not has_remote_source(_finding("Environment variable", "os.environ['SECRET']"))


def test_attack_surface_extracts_literal_python_routes(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "@app.route('/api/items', methods=['POST', 'GET'])\n"
        "def items():\n"
        "    return request.args.get('q', '')\n"
        "@login_required\n"
        "@app.get('/private')\n"
        "def private():\n"
        "    return 'ok'\n",
        encoding="utf-8",
    )
    result = scan_path(tmp_path, cve=False, attack_surface=True)
    routes = result.metadata["attack_surface"]
    assert [(r["path"], r["method"]) for r in routes] == [
        ("/api/items", ["GET", "POST"]), ("/private", ["GET"])
    ]
    assert routes[1]["authentication"] == "present"
    default = scan_path(tmp_path, cve=False)
    assert "attack_surface" not in default.metadata


def test_attack_surface_extracts_express_route(tmp_path: Path) -> None:
    (tmp_path / "server.js").write_text(
        "app.post('/upload', (req, res) => res.send('ok'));\n"
        "router.get('/items', handler);\n", encoding="utf-8",
    )
    result = scan_path(tmp_path, cve=False, attack_surface=True)
    assert [(r["path"], r["method"]) for r in result.metadata["attack_surface"]] == [
        ("/upload", ["POST"]), ("/items", ["GET"])
    ]


def test_remote_filter_excludes_local_findings(tmp_path: Path) -> None:
    (tmp_path / "local.py").write_text(
        "import subprocess\n"
        "import sys\n"
        "value = sys.argv[1]\n"
        "subprocess.run(value, shell=True)\n", encoding="utf-8",
    )
    (tmp_path / "remote.py").write_text(
        "from flask import request\n"
        "import subprocess\n"
        "value = request.args['cmd']\n"
        "subprocess.run(value, shell=True)\n", encoding="utf-8",
    )
    all_result = scan_path(tmp_path, cve=False)
    filtered = scan_path(tmp_path, cve=False, remote_only=True)
    assert any(f.location.file == "local.py" for f in all_result.findings)
    assert filtered.findings
    assert all(has_remote_source(f) for f in filtered.findings)
    assert any(f.location.file == "remote.py" for f in filtered.findings)


def test_new_options_are_opt_in() -> None:
    default = build_parser().parse_args(["."])
    enabled = build_parser().parse_args([".", "--attack-surface", "--remote-only"])
    assert default.attack_surface is False
    assert default.remote_only is False
    assert enabled.attack_surface is True
    assert enabled.remote_only is True
