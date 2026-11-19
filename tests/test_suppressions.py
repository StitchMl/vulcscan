from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from vulcscan.models import Confidence, Finding, Location, Severity
from vulcscan.scanner import scan_path
from vulcscan.suppressions import is_suppressed, suppression_index


def _finding(line: int, rule: str = "PY-CMD-001") -> Finding:
    return Finding(
        rule_id=rule,
        name="Command injection",
        cwe="CWE-78",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category="COMMAND_EXECUTION",
        language="Python",
        location=Location("app.py", line),
        sink="shell",
        evidence="run(x)",
        reason="source to shell",
    )


def _index(text: str):
    return suppression_index([SimpleNamespace(relative="app.py", language="Python", text=text)])


def test_inline_comment_targets_only_same_line_and_rule() -> None:
    index = _index("run(x)  # vulcscan:ignore PY-CMD-001\nrun(y)\n")
    assert is_suppressed(_finding(1), index)
    assert not is_suppressed(_finding(2), index)
    assert not is_suppressed(_finding(1, "PY-SQL-001"), index)


def test_standalone_comment_targets_only_next_physical_line() -> None:
    index = _index("# vulcscan:ignore PY-CMD-001\nrun(x)\nrun(y)\n")
    assert is_suppressed(_finding(2), index)
    assert not is_suppressed(_finding(1), index)
    assert not is_suppressed(_finding(3), index)


def test_string_literals_cannot_inject_suppressions() -> None:
    index = _index("directive = '# vulcscan:ignore PY-CMD-001'\nrun(x)\n")
    assert not is_suppressed(_finding(2), index)


def test_scanner_applies_rule_suppression(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "import subprocess\n"
        "value = request.args['cmd']\n"
        "subprocess.run(value, shell=True)  # vulcscan:ignore PY-CMD-001\n",
        encoding="utf-8",
    )
    result = scan_path(tmp_path, cve=False)
    assert not any(f.rule_id == "PY-CMD-001" and f.location.line == 4 for f in result.findings)
