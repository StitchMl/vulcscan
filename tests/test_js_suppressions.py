from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from vulcscan.models import Confidence, Finding, Location, Severity
from vulcscan.scanner import scan_path
from vulcscan.suppressions import is_suppressed, suppression_index


def _index(text: str, language: str = "JavaScript"):
    return suppression_index([
        SimpleNamespace(relative="app.js", language=language, text=text)
    ])


def _finding(line: int, rule: str = "JS-CMD-001") -> Finding:
    return Finding(
        rule_id=rule, name="Command injection", cwe="CWE-78",
        severity=Severity.HIGH, confidence=Confidence.HIGH,
        category="COMMAND_EXECUTION", language="JavaScript",
        location=Location("app.js", line), sink="exec",
        evidence="exec(value)", reason="test",
    )


def test_javascript_inline_directive_is_rule_and_line_scoped() -> None:
    index = _index(
        "exec(first); // vulcscan:ignore JS-CMD-001\n"
        "exec(second);\n"
    )
    assert is_suppressed(_finding(1), index)
    assert not is_suppressed(_finding(1, "JS-SQL-001"), index)
    assert not is_suppressed(_finding(2), index)


def test_javascript_standalone_directive_targets_next_physical_line() -> None:
    index = _index(
        "// vulcscan:ignore JS-CMD-001\n"
        "exec(first);\n"
        "exec(second);\n"
    )
    assert is_suppressed(_finding(2), index)
    assert not is_suppressed(_finding(1), index)
    assert not is_suppressed(_finding(3), index)


def test_typescript_directive_and_url_string_before_comment() -> None:
    index = _index(
        "const url = 'https://example.invalid'; // vulcscan:ignore JS-CMD-001\n",
        "TypeScript",
    )
    assert is_suppressed(_finding(1), index)


def test_strings_templates_and_block_comments_are_not_directives() -> None:
    index = _index(
        'const s = "// vulcscan:ignore JS-CMD-001";\n'
        + 'const t = ' + chr(96) + '// vulcscan:ignore JS-CMD-001' + chr(96) + ';\n'
        + '/* // vulcscan:ignore JS-CMD-001 */\n'
        + 'exec(value);\n'
    )
    assert not is_suppressed(_finding(1), index)
    assert not is_suppressed(_finding(2), index)
    assert not is_suppressed(_finding(3), index)
    assert not is_suppressed(_finding(4), index)


def test_non_directive_line_comment_cannot_embed_suppression() -> None:
    index = _index("// unrelated // vulcscan:ignore JS-CMD-001\nexec(value);\n")
    assert not is_suppressed(_finding(2), index)


def test_scanner_filters_js_finding_when_explicitly_suppressed(tmp_path: Path) -> None:
    source = (
        "const cp = require('child_process');\n"
        "cp.exec(req.query.cmd); // vulcscan:ignore JS-CMD-001\n"
    )
    (tmp_path / "app.js").write_text(source, encoding="utf-8")
    filtered = scan_path(tmp_path, cve=False)
    assert not any(f.rule_id == "JS-CMD-001" for f in filtered.findings)
    (tmp_path / "app.js").write_text(
        source.replace(" // vulcscan:ignore JS-CMD-001", ""),
        encoding="utf-8",
    )
    full = scan_path(tmp_path, cve=False)
    assert any(f.rule_id == "JS-CMD-001" for f in full.findings)


def test_python_directives_still_work() -> None:
    index = suppression_index([
        SimpleNamespace(
            relative="app.py", language="Python",
            text="# vulcscan:ignore PY-CMD-001\nrun(value)\n",
        )
    ])
    assert (2, "PY-CMD-001") in index["app.py"]
