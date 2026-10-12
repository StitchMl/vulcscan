from __future__ import annotations

import re
from pathlib import Path

import pytest

from vulcscan.scanner import scan_path


# These snippets model unrelated contest services.  Their domain names and data
# shapes deliberately differ from the bundled demonstration applications.
CASES = (
    (
        "billing.py",
        '''import sqlite3
from flask import request

db = sqlite3.connect("billing.db")
customer_key = request.args["customer_key"]
invoice_query = "SELECT invoice_id,total FROM invoices WHERE customer_key='" + customer_key + "'"
db.execute(invoice_query)
''',
        "PY-SQL-001",
        ("customer_key", "invoice_query"),
        ("invoice_id", "total", "customer_key"),
    ),
    (
        "exports.js",
        '''const { exec } = require("child_process");
function inspectArchive(req, res) {
  const archiveName = req.query.archive;
  const inspectCommand = "tar -tf " + archiveName;
  exec(inspectCommand);
}
''',
        "JS-CMD-001",
        ("archiveName", "inspectCommand"),
        ("archiveName", "inspectCommand", "tar"),
    ),
    (
        "hooks.ts",
        '''async function relay(req: Request, res: Response) {
  const callbackEndpoint = req.query.callback;
  const outboundTarget = callbackEndpoint;
  await fetch(outboundTarget);
}
''',
        "JS-SSRF-001",
        ("callbackEndpoint", "outboundTarget"),
        ("callbackEndpoint", "outboundTarget"),
    ),
    (
        "Profile.java",
        '''String displayName = request.getParameter("display_name");
String profileHeading = "<h1>" + displayName + "</h1>";
response.getWriter().write(profileHeading);
''',
        "JAVA-XSS-001",
        ("displayName", "profileHeading"),
        ("displayName", "profileHeading"),
    ),
    (
        "Documents.cs",
        '''var documentSlug = Request.Query["document"];
var requestedDocument = documentSlug;
var contents = File.ReadAllText(requestedDocument);
''',
        "CS-PATH-001",
        ("documentSlug", "requestedDocument"),
        ("documentSlug", "requestedDocument"),
    ),
    (
        "ledger.go",
        '''accountRef := r.URL.Query().Get("account")
ledgerSQL := "SELECT entry_id,amount FROM ledger_entries WHERE account_ref='" + accountRef + "'"
rows, err := db.Query(ledgerSQL)
''',
        "GO-SQL-001",
        ("accountRef", "ledgerSQL"),
        ("entry_id", "amount", "accountRef"),
    ),
    (
        "media.rb",
        '''media_id = params[:media_id]
transcode_command = "ffprobe " + media_id
system(transcode_command)
''',
        "RB-CMD-001",
        ("media_id", "transcode_command"),
        ("media_id", "transcode_command", "ffprobe"),
    ),
    (
        "mirror.php",
        '''<?php
$mirror_url = $_GET['mirror_url'];
$download_target = $mirror_url;
$handle = curl_init($download_target);
''',
        "PHP-SSRF-001",
        ("$mirror_url", "$download_target"),
        ("$mirror_url", "$download_target"),
    ),
)


def _finding(tmp_path: Path, name: str, source: str, rule_id: str):
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / name).write_text(source, encoding="utf-8")
    matches = [item for item in scan_path(tmp_path, cve=False).findings if item.rule_id == rule_id]
    assert matches, f"{rule_id} not detected in {name}"
    return matches[0]


def _contains_any(text: str, symbols: tuple[str, ...]) -> bool:
    return any(symbol in text for symbol in symbols)


@pytest.mark.parametrize(
    ("name", "source", "rule_id", "vector_symbols", "patch_symbols"),
    CASES,
)
def test_competition_guidance_tracks_real_flow_symbols(
    tmp_path: Path,
    name: str,
    source: str,
    rule_id: str,
    vector_symbols: tuple[str, ...],
    patch_symbols: tuple[str, ...],
) -> None:
    finding = _finding(tmp_path, name, source, rule_id)
    vectors = "\n".join(finding.test_vectors)
    patch = next(
        (item.suggested for item in finding.remediations if item.preferred and item.suggested),
        None,
    )

    assert vectors
    assert patch
    assert _contains_any(vectors, vector_symbols), (rule_id, vectors)
    assert _contains_any(patch, patch_symbols), (rule_id, patch)

    # Recoverable flows must not fall back to documentation-only metavariables.
    assert "SELECT ..." not in patch
    assert not re.search(r"\bprogram\b|\bvalue\b", patch)


def test_sql_payload_uses_recovered_query_shape_and_identifier(tmp_path: Path) -> None:
    name, source, rule_id, _, _ = CASES[0]
    finding = _finding(tmp_path, name, source, rule_id)
    vectors = "\n".join(finding.test_vectors)
    patch = next(item.suggested for item in finding.remediations if item.preferred)

    assert "UNION SELECT" in vectors
    assert "2 output columns" in vectors
    assert "customer_key" in vectors
    assert "invoice_id,total" in patch.replace(" ", "")


def test_all_requested_families_are_covered_by_synthetic_services(tmp_path: Path) -> None:
    findings = []
    for name, source, rule_id, _, _ in CASES:
        findings.append(_finding(tmp_path / name.replace(".", "_"), name, source, rule_id))

    families = {item.rule_id.split("-")[1] for item in findings}
    languages = {item.language for item in findings}
    assert {"SQL", "CMD", "XSS", "PATH", "SSRF"} <= families
    assert {"Python", "JavaScript", "TypeScript", "Java", "C#", "Go", "Ruby", "PHP"} <= languages
