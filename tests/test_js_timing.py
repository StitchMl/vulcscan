from __future__ import annotations

from pathlib import Path

from vulcscan.models import Confidence
from vulcscan.scanner import scan_path


def _findings(root: Path, text: str, extension: str = ".js", **options):
    (root / ("app" + extension)).write_text(text, encoding="utf-8")
    result = scan_path(root, cve=False, **options)
    return [item for item in result.findings if item.rule_id == "JS-TIMING-001"]


def test_direct_http_token_compared_to_stored_secret(tmp_path: Path) -> None:
    found = _findings(tmp_path,
        "function authorize(req) {\n"
        "  return req.body.token === storedToken;\n"
        "}\n"
    )
    assert len(found) == 1
    assert found[0].source is not None
    assert found[0].source.line == 2
    assert found[0].location.line == 2
    assert found[0].cwe == "CWE-208"
    assert found[0].confidence == Confidence.MEDIUM
    assert [step.kind for step in found[0].flow] == ["SOURCE", "SINK"]
    assert found[0].test_vectors
    assert all(not r.machine_applicable for r in found[0].remediations)


def test_reverse_http_header_inequality_ts(tmp_path: Path) -> None:
    found = _findings(tmp_path,
        "function auth(req: Request) {\n"
        "  return expectedHmac != req.headers.signature;\n"
        "}\n", ".ts"
    )
    assert len(found) == 1


def test_remote_only_retains_source_tracked_timing_finding(tmp_path: Path) -> None:
    found = _findings(tmp_path,
        "function auth(req) { return req.query.token !== signingSecret; }\n",
        remote_only=True,
    )
    assert len(found) == 1


def test_username_and_numeric_comparisons_are_not_secret_timing(tmp_path: Path) -> None:
    found = _findings(tmp_path,
        "function handler(req) {\n"
        "  return req.body.username === knownUser || Number(req.query.count) == 5;\n"
        "}\n"
    )
    assert found == []


def test_constant_time_crypto_api_is_not_flagged(tmp_path: Path) -> None:
    found = _findings(tmp_path,
        "function auth(req) {\n"
        "  return crypto.timingSafeEqual(left, right);\n"
        "}\n"
    )
    assert found == []


def test_other_network_source_and_strings_comments_are_not_flagged(tmp_path: Path) -> None:
    found = _findings(tmp_path,
        'const text = "req.body.token === storedToken";\n'
        "// req.body.token === storedToken\n"
        "function auth(req) {\n"
        "  return req.body.token === req.query.token;\n"
        "}\n"
    )
    assert found == []


def test_unresolved_intermediate_variable_is_not_guessed(tmp_path: Path) -> None:
    found = _findings(tmp_path,
        "function auth(req) {\n"
        "  const input = req.body.token;\n"
        "  return input === storedToken;\n"
        "}\n"
    )
    assert found == []
