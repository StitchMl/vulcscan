from __future__ import annotations

from pathlib import Path
from vulcscan.scanner import scan_path


def _findings(root: Path, source: str):
    (root / "app.py").write_text(source, encoding="utf-8")
    return [f for f in scan_path(root, cve=False).findings if f.rule_id == "PY-TIMING-001"]


def test_request_token_compared_with_secret(tmp_path: Path) -> None:
    found = _findings(tmp_path,
        "from flask import request\n"
        "def verify():\n"
        "    value = request.headers.get('X-Token')\n"
        "    return value == stored_api_key\n"
    )
    assert len(found) == 1
    assert found[0].source is not None
    assert found[0].source.line == 3
    assert found[0].location.line == 4
    assert found[0].test_vectors
    assert not any(r.machine_applicable for r in found[0].remediations)


def test_direct_request_secret_inequality(tmp_path: Path) -> None:
    found = _findings(tmp_path,
        "from flask import request\n"
        "def verify():\n"
        "    return expected_hmac != request.args['signature']\n"
    )
    assert len(found) == 1


def test_ordinary_numeric_and_username_equality_not_flagged(tmp_path: Path) -> None:
    found = _findings(tmp_path,
        "from flask import request\n"
        "def view():\n"
        "    x = request.args['x']\n"
        "    return int(x) == 5 or x == username\n"
    )
    assert not found


def test_constant_time_and_password_verifier_not_flagged(tmp_path: Path) -> None:
    found = _findings(tmp_path,
        "from flask import request\n"
        "import hmac\n"
        "def check():\n"
        "    value = request.form['token']\n"
        "    return hmac.compare_digest(value, stored_token)\n"
    )
    assert not found


def test_reassigned_remote_value_not_flagged(tmp_path: Path) -> None:
    found = _findings(tmp_path,
        "from flask import request\n"
        "def check():\n"
        "    value = request.form['token']\n"
        "    value = 'local'\n"
        "    return value == stored_token\n"
    )
    assert not found


def test_http_source_is_function_scoped(tmp_path: Path) -> None:
    found = _findings(tmp_path,
        "from flask import request\n"
        "def first():\n"
        "    token = request.form['token']\n"
        "def second():\n"
        "    return token == expected_secret\n"
    )
    assert not found
