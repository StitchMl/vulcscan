from __future__ import annotations

from pathlib import Path

from vulcscan.models import Confidence
from vulcscan.names import generic_secret_is_repetitive, shannon_entropy
from vulcscan.scanner import scan_path


def _secret_findings(root: Path, source: str, filename: str = "secrets.js"):
    (root / filename).write_text(source, encoding="utf-8")
    return [finding for finding in scan_path(root, cve=False).findings if finding.rule_id == "SECRET-001"]


def test_entropy_is_deterministic_and_normalized() -> None:
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("abcd") == 2.0
    assert shannon_entropy("abcabcabcabcabcabc") < 2.5


def test_low_entropy_generic_secret_remains_visible_with_medium_confidence(tmp_path: Path) -> None:
    token = "abcabcabcabcabcabc"
    findings = _secret_findings(tmp_path, f'const api_token = "{token}";\n')
    assert len(findings) == 1
    assert findings[0].confidence == Confidence.MEDIUM
    assert token not in findings[0].evidence
    assert "redacted" in findings[0].evidence.lower()


def test_high_entropy_generic_secret_remains_high_confidence(tmp_path: Path) -> None:
    token = "uT8cYk5M9aS1xV6wQ2nP7rZ4"
    findings = _secret_findings(tmp_path, f'const session_secret = "{token}";\n')
    assert len(findings) == 1
    assert findings[0].confidence == Confidence.HIGH
    assert token not in findings[0].evidence


def test_repetitive_config_value_is_deprioritized_not_dropped(tmp_path: Path) -> None:
    findings = _secret_findings(tmp_path, "API_TOKEN=abcabcabcabcabcabc\n", ".env")
    assert len(findings) == 1
    assert findings[0].confidence == Confidence.MEDIUM


def test_known_token_prefix_is_still_high_confidence(tmp_path: Path) -> None:
    token = "ghp_" + "A" * 36
    findings = _secret_findings(tmp_path, f'const example = "{token}";\n')
    assert len(findings) == 1
    assert findings[0].confidence == Confidence.HIGH
    assert token not in findings[0].evidence


def test_identifiers_without_credentials_and_placeholders_not_downgraded(tmp_path: Path) -> None:
    assert not generic_secret_is_repetitive("abcabcabcabcabcabc", "example")
    assert _secret_findings(tmp_path, 'const api_token = "placeholder-for-local-token";\n') == []
