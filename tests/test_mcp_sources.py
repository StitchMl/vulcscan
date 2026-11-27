from __future__ import annotations

from vulcscan.python_analysis import analyze_python


def _rules(source: str) -> list[str]:
    findings, error = analyze_python("mcp_server.py", source)
    assert error is None
    return [finding.rule_id for finding in findings]


def test_mcp_tool_argument_is_remote_for_path_traversal_analysis() -> None:
    findings, error = analyze_python(
        "mcp_server.py",
        "from pathlib import Path\n"
        "from mcp.server.fastmcp import FastMCP\n"
        "server = FastMCP('docs')\n"
        "@server.tool()\n"
        "def read_document(filename: str):\n"
        "    return (Path('/srv/docs') / filename).read_text()\n",
    )

    assert error is None
    path_findings = [item for item in findings if item.rule_id == "PY-PATH-001"]
    assert len(path_findings) == 1
    assert path_findings[0].source is not None
    assert path_findings[0].source.line == 5
    assert "MCP tool arguments" in path_findings[0].flow[0].description


def test_mcp_tool_argument_reaches_sql_sink() -> None:
    assert "PY-SQL-001" in _rules(
        "from fastmcp import FastMCP\n"
        "mcp = FastMCP('catalog')\n"
        "@mcp.tool\n"
        "def find_product(term: str, db):\n"
        "    return db.execute('SELECT * FROM products WHERE name=' + term)\n",
    )


def test_unrelated_server_tool_decorator_is_not_assumed_to_be_mcp() -> None:
    assert not _rules(
        "class LocalServer:\n"
        "    def tool(self, function):\n"
        "        return function\n"
        "server = LocalServer()\n"
        "@server.tool\n"
        "def helper(filename: str):\n"
        "    return open(filename).read()\n",
    )
