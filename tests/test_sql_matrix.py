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
    (tmp_path / "app.php").write_text(
        '''<?php
$name = $_GET['name'];
$stmt = $db->prepare("SELECT * FROM users WHERE name = ?");
$stmt->bind_param("s", $name);
$stmt->execute();
''',
        encoding="utf-8",
    )
    (tmp_path / "App.java").write_text(
        '''String name = request.getParameter("name");
PreparedStatement stmt = connection.prepareStatement("SELECT * FROM users WHERE name = ?");
stmt.setString(1, name);
''',
        encoding="utf-8",
    )
    (tmp_path / "App.cs").write_text(
        '''var name = Request.Query["name"];
var command = new SqlCommand("SELECT * FROM users WHERE name = @name", connection);
command.Parameters.AddWithValue("@name", name);
''',
        encoding="utf-8",
    )
    (tmp_path / "app.go").write_text(
        '''name := r.URL.Query().Get("name")
db.Query("SELECT * FROM users WHERE name = ?", name)
''',
        encoding="utf-8",
    )
    (tmp_path / "app.rb").write_text(
        '''name = params[:name]
User.where("name = ?", name)
''',
        encoding="utf-8",
    )
    (tmp_path / "app.c").write_text(
        '''void lookup(sqlite3 *db, const char *name) {
    sqlite3_prepare_v2(db, "SELECT * FROM users WHERE name = ?", -1, &stmt, 0);
    sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT);
}
''',
        encoding="utf-8",
    )

    result = scan(ScanConfig(tmp_path, offline=True, cve=False))

    assert not [item for item in result.findings if item.cwe == "CWE-89"]


@pytest.mark.parametrize(
    ("filename", "source", "rule_id"),
    [
        (
            "sequelize.js",
            '''function view(req) {
  const fragment = req.query.order;
  return sequelize.literal(fragment);
}
''',
            "JS-SQL-001",
        ),
        (
            "gorm.go",
            '''fragment := r.URL.Query().Get("filter")
db.Raw("SELECT * FROM users WHERE " + fragment)
''',
            "GO-SQL-001",
        ),
    ],
)
def test_orm_raw_sql_sinks_are_reported(
    tmp_path: Path,
    filename: str,
    source: str,
    rule_id: str,
) -> None:
    (tmp_path / filename).write_text(source, encoding="utf-8")

    result = scan(ScanConfig(tmp_path, offline=True, cve=False))

    assert rule_id in {item.rule_id for item in result.findings}
