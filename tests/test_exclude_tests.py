from __future__ import annotations

from pathlib import Path

from vulcscan.cli import build_parser
from vulcscan.scanner import scan_path


def _write(path: Path, content: str = "value = 1\n") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_excluding_tests_is_strictly_opt_in(tmp_path: Path) -> None:
    _write(tmp_path / "src" / "app.py")
    _write(tmp_path / "tests" / "test_app.py")
    _write(tmp_path / "src" / "test_auth.py")
    _write(tmp_path / "src" / "route.spec.ts")
    _write(tmp_path / "src" / "search_test.go")
    _write(tmp_path / "fixtures" / "seed.py")
    _write(tmp_path / "migrations" / "001.py")
    default = scan_path(tmp_path, cve=False)
    selected = scan_path(tmp_path, cve=False, exclude_tests=True)
    assert default.metadata["files_analyzed"] == 7
    assert selected.metadata["files_analyzed"] == 2
    assert selected.metadata["files_discovered"] == 5
    assert "migrations" not in str(selected.errors)


def test_test_source_findings_retained_by_default(tmp_path: Path) -> None:
    vulnerable = (
        "import subprocess\n"
        "from flask import request\n"
        "value = request.args['cmd']\n"
        "subprocess.run(value, shell=True)\n"
    )
    _write(tmp_path / "src" / "app.py", vulnerable)
    _write(tmp_path / "tests" / "test_app.py", vulnerable)
    default = scan_path(tmp_path, cve=False)
    filtered = scan_path(tmp_path, cve=False, exclude_tests=True)
    assert any(f.location.file == "tests/test_app.py" for f in default.findings)
    assert all(f.location.file != "tests/test_app.py" for f in filtered.findings)
    assert any(f.location.file == "src/app.py" for f in filtered.findings)


def test_opt_in_cli_switch_does_not_affect_defaults() -> None:
    parser = build_parser()
    assert parser.parse_args(["."]).exclude_tests is False
    assert parser.parse_args([".", "--exclude-tests"]).exclude_tests is True


def test_production_named_test_helper_is_not_excluded(tmp_path: Path) -> None:
    _write(tmp_path / "src" / "test_helpers.py")
    _write(tmp_path / "src" / "contest.py")
    result = scan_path(tmp_path, cve=False, exclude_tests=True)
    assert result.metadata["files_analyzed"] == 1
