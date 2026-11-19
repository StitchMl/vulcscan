from __future__ import annotations

import re
from pathlib import Path

from vulcscan.scanner import scan_path


def _scan(tmp_path: Path, filename: str, text: str):
    (tmp_path / filename).write_text(text, encoding="utf-8")
    return scan_path(tmp_path, cve=False).findings


def test_loose_php_auth_comparison_with_remote_input(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path, "login.php",
        "<?php\n"
        "$input = $_POST['token'];\n"
        "if ($stored_token == $input) { allow(); }\n",
    )
    matches = [finding for finding in findings if finding.rule_id == "PHP-TYPE-JUGGLING-001"]
    assert len(matches) == 1
    assert matches[0].location.line == 3
    assert matches[0].cwe == "CWE-697"
    assert matches[0].remediations
    assert not any(item.machine_applicable for item in matches[0].remediations)


def test_direct_request_inequality_is_flagged(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path, "verify.php",
        '<?php if ($expected_hmac != $_GET["signature"]) { deny(); }\n',
    )
    assert any(f.rule_id == "PHP-TYPE-JUGGLING-001" for f in findings)


def test_php_strict_and_purpose_built_auth_comparisons_are_safe(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path, "strict.php",
        "<?php\n"
        "$input = $_POST['token'];\n"
        "if ($token === $input) { allow(); }\n"
        "if ($token !== $input) { deny(); }\n"
        "if (hash_equals($token, $input)) { allow(); }\n"
        "if (password_verify($input, $stored_hash)) { allow(); }\n"
        "if ($attempts == 0) { deny(); }\n",
    )
    assert not any(f.rule_id == "PHP-TYPE-JUGGLING-001" for f in findings)


def test_comments_and_unrelated_loose_comparisons_not_flagged(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path, "safe.php",
        "<?php\n"
        "// if ($token == $_POST['token']) { allow(); }\n"
        "if ($counter == $retry) { skip(); }\n",
    )
    assert not any(f.rule_id == "PHP-TYPE-JUGGLING-001" for f in findings)


def test_modern_token_formats_are_redacted(tmp_path: Path) -> None:
    formats = (
        "sk-proj-" + "A1b2C3d4E5f6G7h8I9j0K1l2",
        "sk-ant-" + "A1b2C3d4E5f6G7h8I9j0K1l2",
        "hf_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4",
        "npm_" + "A1b2C3d4E5f6G7h8I9j0K1l2",
        "pypi-" + "A1b2C3d4E5f6G7h8I9j0K1l2",
    )
    findings = _scan(tmp_path, "credentials.js", "\n".join(formats) + "\n")
    secrets = [f for f in findings if f.rule_id == "SECRET-001"]
    assert len(secrets) == len(formats)
    for finding in secrets:
        assert "redacted" in finding.evidence.lower()
        assert not any(token in finding.evidence for token in formats)


def test_example_file_does_not_emit_new_token_findings(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path, "credentials.example.js",
        "sk-proj-" + "A1b2C3d4E5f6G7h8I9j0K1l2" + "\n",
    )
    assert not [f for f in findings if f.rule_id == "SECRET-001"]
