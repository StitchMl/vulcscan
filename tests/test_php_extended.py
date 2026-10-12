from vulcscan.lexical import lexical_findings
from vulcscan.structured import analyze_structured
from vulcscan.scanner import scan_path


def test_php_url_stream_is_also_ssrf() -> None:
    source = "<?php $url = $_GET['url']; $data = file_get_contents($url);"
    ids = {item.rule_id for item in analyze_structured("import.php", source, "PHP")}
    assert "PHP-SSRF-001" in ids


def test_php_sql_finding_has_payload_and_patch_preview() -> None:
    source = "<?php $q = $_GET['q']; $sql = \"SELECT * FROM items WHERE name='\" . $q . \"'\"; $result = $db->query($sql);"
    finding = next(item for item in analyze_structured("search.php", source, "PHP") if item.rule_id == "PHP-SQL-001")
    preferred = finding.remediations[0]
    assert preferred.current == "->query($sql)"
    assert "$db->prepare" in (preferred.suggested or "")
    assert preferred.machine_applicable is False


def test_php_unescaped_database_field_is_potential_xss() -> None:
    source = """<?php
echo htmlspecialchars($row['author']) . ': ' . $row['comment'];
"""
    findings = lexical_findings("review.php", "review.php", "PHP", source)
    assert [item.rule_id for item in findings].count("PHP-XSS-001") == 1


def test_php_reflected_variable_is_xss() -> None:
    source = "<?php $query = $_GET['q']; echo '<p>No result for ' . $query . '</p>';"
    ids = {item.rule_id for item in lexical_findings("search.php", "search.php", "PHP", source)}
    assert "PHP-XSS-001" in ids


def test_php_fully_encoded_output_is_not_xss() -> None:
    source = "<?php echo htmlspecialchars($row['comment'], ENT_QUOTES);"
    assert "PHP-XSS-001" not in {
        item.rule_id for item in lexical_findings("safe.php", "safe.php", "PHP", source)
    }


def test_php_numeric_cast_and_json_encoding_are_not_xss() -> None:
    source = """<?php
echo "<a href='?id=" . (int)$row['id'] . "'>";
echo json_encode(['discount' => $row['discount']]);
"""
    assert "PHP-XSS-001" not in {
        item.rule_id for item in lexical_findings("safe.php", "safe.php", "PHP", source)
    }


def test_check_then_decrement_is_reported() -> None:
    source = """<?php
$q = $db->prepare('SELECT uses_remaining FROM coupon WHERE code = ?');
$coupon = $q->get_result()->fetch_assoc();
if ($coupon['uses_remaining'] > 0) {
  $q = $db->prepare('UPDATE coupon SET uses_remaining = uses_remaining - 1 WHERE code = ?');
}
"""
    ids = {item.rule_id for item in lexical_findings("checkout.php", "checkout.php", "PHP", source)}
    assert "DB-RACE-001" in ids


def test_atomic_conditional_decrement_is_not_reported() -> None:
    source = "<?php $db->query('UPDATE coupon SET uses_remaining = uses_remaining - 1 WHERE code = ? AND uses_remaining > 0');"
    ids = {item.rule_id for item in lexical_findings("checkout.php", "checkout.php", "PHP", source)}
    assert "DB-RACE-001" not in ids


def test_scan_attaches_deterministic_test_vectors(tmp_path) -> None:
    (tmp_path / "v.php").write_text("<?php $q = $_GET['q']; $db->query('SELECT * FROM x WHERE y=' . $q);", encoding="utf-8")
    finding = next(item for item in scan_path(tmp_path, offline=True, cve=False).findings if item.rule_id == "PHP-SQL-001")
    assert "' OR '1'='1' -- " in finding.test_vectors[0]
    assert finding.as_dict()["test_vectors"] == finding.test_vectors


def test_active_svg_is_scanned(tmp_path) -> None:
    (tmp_path / "avatar.svg").write_text('<svg onload="alert(1)"></svg>', encoding="utf-8")
    result = scan_path(tmp_path, offline=True, cve=False)
    assert "SVG-ACTIVE-001" in {item.rule_id for item in result.findings}
    assert result.metadata["files_analyzed"] == 1
