from __future__ import annotations

import json
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from vulcscan.models import ScanConfig
from vulcscan.scanner import scan


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).parent / "fixtures"


def _scan(root: Path, **changes: object):
    values: dict[str, object] = {
        "root": root.resolve(),
        "offline": True,
        "cve": False,
    }
    values.update(changes)
    return scan(ScanConfig(**values))


def test_discovery_finds_python_javascript_and_dotfiles() -> None:
    result = _scan(FIXTURES)

    assert result.metadata["files_discovered"] >= 9
    assert result.metadata["files_analyzed"] >= 8
    assert {name.casefold() for name in result.metadata["languages"]} >= {
        "python",
        "javascript",
    }
    assert any(finding.location.file.endswith("robustness/.env") for finding in result.findings)


def test_safe_fixtures_do_not_trigger_taint_rules() -> None:
    result = _scan(FIXTURES / "safe")
    high_signal_rules = {
        "PY-CMD-001",
        "JS-CMD-001",
        "PY-SQL-001",
        "JS-SQL-001",
        "PY-CODE-001",
        "JS-CODE-001",
        "PY-PATH-001",
        "JS-PATH-001",
        "PY-SSRF-001",
        "JS-SSRF-001",
        "PY-DESER-001",
        "JS-DESER-001",
    }

    assert high_signal_rules.isdisjoint(item.rule_id for item in result.findings)


def test_malformed_files_and_untrusted_setup_do_not_abort_scan() -> None:
    result = _scan(FIXTURES / "robustness")

    assert result.metadata["files_discovered"] >= 5
    assert result.metadata["files_analyzed"] >= 3
    assert isinstance(result.errors, list)


def test_directory_with_spaces_scans_on_current_platform() -> None:
    result = _scan(FIXTURES / "robustness" / "path with spaces")

    assert result.metadata["files_discovered"] == 1
    assert result.metadata["files_analyzed"] == 1
    assert result.findings == []


def test_default_exclusions_skip_dependency_trees(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    excluded = tmp_path / "node_modules" / "package"
    excluded.mkdir(parents=True)
    (excluded / "index.js").write_text(
        'const password = "prod-password-from-vendored-code";\n',
        encoding="utf-8",
    )

    result = _scan(tmp_path)

    assert all("node_modules" not in item.location.file for item in result.findings)
    assert result.metadata["files_discovered"] == 1


def test_custom_exclude_pattern_uses_repository_relative_paths(tmp_path: Path) -> None:
    generated = tmp_path / "generated"
    generated.mkdir()
    (generated / "unsafe.py").write_text(
        'password = "prod-password-in-generated-code"\n',
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")

    result = _scan(tmp_path, excludes=("generated/**",))

    assert all(not item.location.file.startswith("generated/") for item in result.findings)


def test_binary_and_oversized_files_are_skipped(tmp_path: Path) -> None:
    (tmp_path / "binary.py").write_bytes(
        b"\x00\x01password = 'prod-password-inside-binary'\n"
    )
    (tmp_path / "large.py").write_text(
        "# padding\n" + "x" * 512 + '\npassword = "prod-password-after-limit"\n',
        encoding="utf-8",
    )

    result = _scan(tmp_path, max_file_size=128)

    assert result.findings == []
    assert result.metadata["files_skipped"] == 2


def test_crlf_keeps_source_line_numbers(tmp_path: Path) -> None:
    source = (
        "from flask import request\r\n"
        "import subprocess\r\n"
        "command = request.args['command']\r\n"
        "subprocess.run(command, shell=True)\r\n"
    )
    (tmp_path / "app.py").write_bytes(source.encode("utf-8"))

    result = _scan(tmp_path)
    finding = next(item for item in result.findings if item.rule_id == "PY-CMD-001")

    assert finding.location.line == 4
    assert finding.source is not None
    assert finding.source.line == 3


def test_output_paths_are_relative_and_platform_stable() -> None:
    result = _scan(FIXTURES / "vulnerable")

    assert result.findings
    for finding in result.findings:
        assert not Path(finding.location.file).is_absolute()
        assert "\\" not in finding.location.file


def test_scan_order_is_deterministic() -> None:
    first = _scan(FIXTURES / "vulnerable")
    second = _scan(FIXTURES / "vulnerable")

    assert [item.as_dict() for item in first.findings] == [
        item.as_dict() for item in second.findings
    ]
    assert [item.as_dict() for item in first.dependencies] == [
        item.as_dict() for item in second.dependencies
    ]
    assert [item.as_dict() for item in first.errors] == [
        item.as_dict() for item in second.errors
    ]


def test_offline_mode_performs_no_network_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "requirements.txt").write_text("urllib3==1.26.0\n", encoding="utf-8")

    def deny_network(*_args: object, **_kwargs: object) -> None:
        pytest.fail("offline scan attempted network access")

    monkeypatch.setattr(socket.socket, "connect", deny_network)
    result = _scan(tmp_path, cve=True)

    assert result.metadata["network_access"] == "DISABLED"


def test_symlink_outside_root_is_not_followed(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / "app.py").write_text("value = 1\n", encoding="utf-8")
    target = outside / "unsafe.py"
    target.write_text('password = "prod-password-outside-root"\n', encoding="utf-8")
    link = root / "linked.py"
    try:
        link.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"platform cannot create a file symlink: {exc}")

    result = _scan(root)

    assert all(item.location.file != "linked.py" for item in result.findings)
    assert result.metadata["files_discovered"] == 1


def test_cli_emits_json_for_a_path_with_spaces(tmp_path: Path) -> None:
    root = tmp_path / "service with spaces"
    root.mkdir()
    (root / "app.py").write_text("value = 1\n", encoding="utf-8")

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "vulcscan",
            str(root),
            "--offline",
            "--no-cve",
            "--format",
            "json",
        ],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )

    assert completed.returncode == 0, completed.stderr
    report = json.loads(completed.stdout)
    assert set(report) == {
        "metadata",
        "findings",
        "dependencies",
        "dependency_vulnerabilities",
        "errors",
    }
    assert report["metadata"]["network_access"] == "DISABLED"


def test_source_launcher_accepts_the_documented_command(tmp_path: Path) -> None:
    root = tmp_path / "service"
    root.mkdir()
    (root / "app.py").write_text("value = 1\n", encoding="utf-8")

    completed = subprocess.run(
        [
            sys.executable,
            str(PROJECT_ROOT / "vulcscan.py"),
            str(root),
            "--offline",
            "--no-cve",
            "--format",
            "json",
        ],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )

    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout)["metadata"]["files_analyzed"] == 1
