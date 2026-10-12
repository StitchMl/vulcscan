from __future__ import annotations

from pathlib import Path

import pytest

from vulcscan.models import ScanConfig
from vulcscan.scanner import scan


SQL_CASES = (
    (
        "app.py",
        '''from flask import request

def view(cursor):
    name = request.args["name"]
    cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")
''',
        "PY-SQL-001",
    ),
    (
        "app.js",
        '''function view(req, res) {
  const sql = `SELECT * FROM users WHERE name = '${req.query.name}'`;
  database.query(sql);
}
''',
        "JS-SQL-001",
    ),
    (
        "app.php",
        '''<?php
$name = $_GET['name'];
$pdo->query("SELECT * FROM users WHERE name = '" . $name . "'");
''',
        "PHP-SQL-001",
    ),
    (
        "App.java",
        '''String name = request.getParameter("name");
String sql = "SELECT * FROM users WHERE name = '" + name + "'";
statement.executeQuery(sql);
''',
        "JAVA-SQL-001",
    ),
    (
        "App.cs",
        '''var name = Request.Query["name"];
var sql = "SELECT * FROM users WHERE name = '" + name + "'";
var command = new SqlCommand(sql, connection);
''',
        "CS-SQL-001",
    ),
    (
        "app.go",
        '''name := r.URL.Query().Get("name")
query := "SELECT * FROM users WHERE name = '" + name + "'"
db.Query(query)
''',
        "GO-SQL-001",
    ),
    (
        "app.rb",
        '''name = params[:name]
query = "SELECT * FROM users WHERE name = '#{name}'"
connection.execute(query)
''',
        "RB-SQL-001",
    ),
    (
        "app.c",
        '''void run(sqlite3 *db, int argc, char **argv) {
    sqlite3_exec(db, argv[1], 0, 0, 0);
}
''',
        "C-SQL-001",
    ),
    (
        "app.ps1",
        '''$query = $Request.Query.sql
Invoke-Sqlcmd -Query $query
''',
        "PS-SQL-001",
    ),
)


@pytest.mark.parametrize(("filename", "source", "rule_id"), SQL_CASES)
def test_sql_injection_matrix(
    tmp_path: Path,
    filename: str,
    source: str,
    rule_id: str,
) -> None:
    (tmp_path / filename).write_text(source, encoding="utf-8")

    result = scan(ScanConfig(tmp_path, offline=True, cve=False))

    matches = [item for item in result.findings if item.rule_id == rule_id]
    assert matches, [
        (item.rule_id, item.location.file, item.location.line)
        for item in result.findings
    ]
    assert matches[0].source is not None
    assert matches[0].cwe == "CWE-89"


def test_parameterized_sql_is_not_reported(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        '''from flask import request

def view(cursor):
    name = request.args["name"]
    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
''',
        encoding="utf-8",
    )
    (tmp_path / "app.js").write_text(
        '''function view(req) {
  database.query("SELECT * FROM users WHERE name = ?", [req.query.name]);
}
''',
        encoding="utf-8",
    )

    result = scan(ScanConfig(tmp_path, offline=True, cve=False))

    assert not [item for item in result.findings if item.cwe == "CWE-89"]
