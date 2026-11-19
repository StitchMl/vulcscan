from __future__ import annotations

from pathlib import Path

from vulcscan.models import ScanResult
from vulcscan.report import render_text
from vulcscan.scanner import scan_path


def test_opt_in_attack_surface_precedes_priority_index(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "import subprocess\n"
        "@app.get('/lookup')\n"
        "def lookup():\n"
        "    command = request.args['command']\n"
        "    subprocess.run(command, shell=True)\n",
        encoding="utf-8",
    )
    result = scan_path(tmp_path, cve=False, attack_surface=True)
    report = render_text(result, color=False, width=88)
    assert "ATTACK SURFACE" in report
    assert "GET /lookup" in report
    assert "auth: unknown" in report
    assert report.index("ATTACK SURFACE") < report.index("PRIORITY INDEX")
    assert "VERIFY (review before use)" in report
    assert max(len(line) for line in report.splitlines()) <= 88


def test_default_text_report_does_not_add_inventory() -> None:
    result = ScanResult(metadata={"root": "/tmp/project"})
    report = render_text(result)
    assert "ATTACK SURFACE" not in report


def test_empty_opt_in_inventory_is_not_mistaken_for_no_routes() -> None:
    result = ScanResult(metadata={"root": "/tmp/project", "attack_surface": []})
    report = render_text(result)
    assert "ATTACK SURFACE" in report
    assert "No statically identified endpoints." in report


def test_imported_handler_location_and_rules_are_visible() -> None:
    result = ScanResult(metadata={
        "root": "/tmp/project",
        "attack_surface": [
            {
                "method": ["GET"],
                "path": "/search",
                "file": "routes.js",
                "line": 3,
                "handler": "lookup",
                "handler_file": "controllers.js",
                "authentication": "unknown",
                "finding_rules": ["JS-SQL-001"],
            }
        ],
    })
    report = render_text(result)
    assert "routes.js:3 -> controllers.js (lookup)" in report
    assert "JS-SQL-001" in report
