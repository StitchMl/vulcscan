"""Controlled service-contract checks for generated command patches.

The scanner must never execute target code; this fixture models benign endpoint
semantics with a recording process rather than spawning an OS command.
"""
from __future__ import annotations

import ast
import shlex
from pathlib import Path

from vulcscan.report import render_unified_diff
from vulcscan.scanner import scan_path


def _simulate_process(command: str | list[str], *, shell: bool = False) -> str:
    """Simulate a fixed git command without starting a subprocess."""
    argv = shlex.split(command) if shell else command
    assert argv[:3] == ["git", "status", "--"]
    return " ".join(argv[3:])


def test_generated_command_patch_preserves_benign_endpoint_contract(tmp_path: Path) -> None:
    original = (
        "import subprocess\n"
        "from flask import request\n"
        "def endpoint():\n"
        "    return subprocess.run(f\"echo {request.args['name']}\", shell=True)\n"
    )
    target = tmp_path / "app.py"
    target.write_text(original, encoding="utf-8")

    result = scan_path(tmp_path, cve=False, only_files=frozenset({"app.py"}))
    findings = [
        finding for finding in result.findings
        if finding.rule_id == "PY-CMD-001" and finding.source is not None
    ]
    assert len(findings) == 1
    patches = [
        fix for fix in findings[0].remediations
        if fix.machine_applicable and fix.current and fix.suggested
    ]
    assert len(patches) == 1
    patch = patches[0]
    assert patch.suggested == 'subprocess.run(["git", "status", "--", request.args[\'path\']])'

    diff = render_unified_diff(result, tmp_path)
    assert '+    return subprocess.run(["git", "status", "--", request.args[\'path\']])' in diff
    assert target.read_text(encoding="utf-8") == original
    updated = original.replace(patch.current, patch.suggested, 1)
    ast.parse(updated)

    for value in ("ready", "healthy", "ok"):
        old_response = _simulate_process(f"git status -- {value}", shell=True)
        new_response = _simulate_process(["git", "status", "--", value])
        assert new_response == old_response

    injection = "ready; echo UNSAFE"
    literal_response = _simulate_process(["git", "status", "--", injection])
    assert literal_response == injection

    target.write_text(updated, encoding="utf-8")
    scanned = scan_path(tmp_path, cve=False, only_files=frozenset({"app.py"}))
    assert not [finding for finding in scanned.findings if finding.rule_id == "PY-CMD-001"]
    assert scanned.metadata["files_analyzed"] == 1
