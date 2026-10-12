from pathlib import Path

import pytest

from vulcscan.scanner import scan_path


@pytest.mark.parametrize(
    ("name", "source", "rule_id", "patch_fragment"),
    [
        (
            "app.py",
            "import sqlite3\nfrom flask import request\ndb=sqlite3.connect(':memory:')\nvalue=request.args['id']\ndb.execute(f'SELECT * FROM users WHERE id={value}')\n",
            "PY-SQL-001",
            "cursor.execute",
        ),
        (
            "app.js",
            "const cp=require('child_process');\napp.get('/', (req,res) => { cp.exec('echo ' + req.query.q); });\n",
            "JS-CMD-001",
            "execFile",
        ),
        (
            "app.php",
            '<?php echo $_GET["q"]; ?>',
            "PHP-XSS-001",
            "htmlspecialchars",
        ),
    ],
)
def test_scan_adds_language_and_sink_specific_guidance(
    tmp_path: Path, name: str, source: str, rule_id: str, patch_fragment: str
) -> None:
    (tmp_path / name).write_text(source, encoding="utf-8")
    finding = next(item for item in scan_path(tmp_path, cve=False).findings if item.rule_id == rule_id)

    assert finding.remediations[0].preferred is True
    assert sum(item.preferred for item in finding.remediations) == 1
    assert any(patch_fragment in (item.suggested or "") for item in finding.remediations)
    assert any(finding.sink in item.guidance for item in finding.remediations)
    assert all(f"{name}:{finding.location.line}" in vector for vector in finding.test_vectors[:1])


def test_sql_vectors_are_contextual_and_non_destructive(tmp_path: Path) -> None:
    source = "<?php $id = $_GET['id']; $db->query(\"SELECT * FROM users WHERE id=\" . $id);"
    (tmp_path / "search.php").write_text(source, encoding="utf-8")
    finding = next(item for item in scan_path(tmp_path, cve=False).findings if item.rule_id == "PHP-SQL-001")

    joined = "\n".join(finding.test_vectors)
    assert "search.php:" in joined
    assert finding.sink in joined
    assert "DROP " not in joined.upper()
    assert "DELETE " not in joined.upper()
    assert "paired predicates" in joined


def test_php_sql_patch_uses_flow_variables_and_preserves_like_wildcards(tmp_path: Path) -> None:
    source = '''<?php
$term = $_GET['q'];
$sql = "SELECT id FROM products WHERE name LIKE '%" . $term . "%'";
$db->query($sql);
'''
    (tmp_path / "search.php").write_text(source, encoding="utf-8")
    finding = next(item for item in scan_path(tmp_path, cve=False).findings if item.rule_id == "PHP-SQL-001")
    patch = finding.remediations[0].suggested or ""

    assert 'WHERE name LIKE ?' in patch
    assert '$stmt->bind_param("s", "%" . $term . "%")' in patch
    assert "SELECT ..." not in patch
    joined = "\n".join(finding.test_vectors)
    assert "UNION SELECT" in joined
    assert "CURRENT_USER" in joined
    assert "Unauthorized-row proof" in joined


def test_authentication_sql_vector_proves_bypass_with_invalid_password(tmp_path: Path) -> None:
    source = '''<?php
$user = $_POST['username'];
$password = $_POST['password'];
$sql = "SELECT * FROM admin_users WHERE username='" . $user . "' AND password='" . $password . "'";
$db->query($sql);
'''
    (tmp_path / "login.php").write_text(source, encoding="utf-8")
    finding = next(item for item in scan_path(tmp_path, cve=False).findings if item.rule_id == "PHP-SQL-001")

    proof = finding.test_vectors[0]
    assert "Authentication proof" in proof
    assert "invalid password" in proof
    assert "protected page" in proof


@pytest.mark.parametrize(
    ("name", "source", "rule_id"),
    [
        (
            "App.java",
            'String id = request.getParameter("id");\nString sql = "SELECT id, email FROM users WHERE id=" + id;\nstatement.executeQuery(sql);\n',
            "JAVA-SQL-001",
        ),
        (
            "app.go",
            'id := r.URL.Query().Get("id")\nquery := "SELECT id, email FROM users WHERE id=" + id\ndb.Query(query)\n',
            "GO-SQL-001",
        ),
    ],
)
def test_data_read_proof_is_language_independent(
    tmp_path: Path, name: str, source: str, rule_id: str
) -> None:
    (tmp_path / name).write_text(source, encoding="utf-8")
    finding = next(item for item in scan_path(tmp_path, cve=False).findings if item.rule_id == rule_id)

    joined = "\n".join(finding.test_vectors)
    assert "Unauthorized-row proof" in joined
    assert "UNION SELECT" in joined
    assert "CURRENT_USER" in joined


def test_rule_without_special_patch_still_gets_location_specific_vector(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import Flask\napp = Flask(__name__)\napp.run(debug=True)\n",
        encoding="utf-8",
    )
    finding = next(item for item in scan_path(tmp_path, cve=False).findings if item.rule_id == "DEBUG-001")

    assert finding.test_vectors
    assert f"app.py:{finding.location.line}" in finding.test_vectors[0]
