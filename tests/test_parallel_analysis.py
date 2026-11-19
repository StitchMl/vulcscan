from __future__ import annotations

from pathlib import Path

import pytest

from vulcscan.cli import build_parser
from vulcscan.scanner import scan_path


def _fixture(root: Path) -> None:
    (root / "app.py").write_text(
        "import subprocess\n"
        "from flask import request\n"
        "def handler():\n"
        "    value = request.args['cmd']\n"
        "    subprocess.run(value, shell=True)\n",
        encoding="utf-8",
    )
    (root / "routes.js").write_text(
        "import { run } from './service.js';\n"
        "function handler(req) { run(req.query.cmd); }\n",
        encoding="utf-8",
    )
    (root / "service.js").write_text(
        "const cp = require('child_process');\n"
        "export function run(value) { cp.exec(value); }\n",
        encoding="utf-8",
    )
    (root / "legacy.c").write_text(
        "void run(char **argv) { char out[8]; strcpy(out, argv[1]); }\n",
        encoding="utf-8",
    )
    (root / "requirements.txt").write_text("example-package==1.2.3\n", encoding="utf-8")
    (root / "helper.php").write_text(
        "<?php $x = $_GET['token']; if ($stored_token == $x) allow();\n",
        encoding="utf-8",
    )
    (root / "a.bin").write_bytes(b"\x7fELF" + b"TESTING\x00" + b"gets\x00")
    (root / "b.bin").write_bytes(b"MZ" + b"\x00" * 80 + b"strcpy\x00")


def _stable(result):
    data = result.as_dict()
    data["metadata"].pop("scan_duration", None)
    return data


def test_parallel_matches_serial_findings_and_dependencies(tmp_path: Path) -> None:
    _fixture(tmp_path)
    serial = scan_path(tmp_path, cve=False, workers=1, attack_surface=True)
    for workers in (2, 4, 8):
        parallel = scan_path(tmp_path, cve=False, workers=workers, attack_surface=True)
        assert _stable(parallel) == _stable(serial)
    assert serial.findings
    assert serial.dependencies
    assert any(f.location.file == "routes.js" for f in serial.findings)


def test_parallel_is_deterministic_across_repeated_runs(tmp_path: Path) -> None:
    _fixture(tmp_path)
    baseline = _stable(scan_path(tmp_path, cve=False, workers=4))
    for _ in range(3):
        assert _stable(scan_path(tmp_path, cve=False, workers=4)) == baseline


def test_single_file_and_empty_repository(tmp_path: Path) -> None:
    assert _stable(scan_path(tmp_path, cve=False, workers=4)) == _stable(
        scan_path(tmp_path, cve=False, workers=1)
    )
    (tmp_path / "app.js").write_text("const x = 1;\n", encoding="utf-8")
    assert _stable(scan_path(tmp_path, cve=False, workers=8)) == _stable(
        scan_path(tmp_path, cve=False, workers=1)
    )


def test_workers_cli_defaults_and_ranges(tmp_path: Path) -> None:
    parser = build_parser()
    assert parser.parse_args([str(tmp_path)]).workers == 1
    assert parser.parse_args([str(tmp_path), "--workers", "4"]).workers == 4
    for invalid in (0, -1, 9):
        with pytest.raises(ValueError, match="workers must be between"):
            scan_path(tmp_path, cve=False, workers=invalid)
