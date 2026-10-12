from __future__ import annotations

from pathlib import Path

import pytest

from vulcscan.models import ScanConfig
from vulcscan.scanner import scan


XSS_CASES = (
    (
        "app.py",
        '''from flask import request, make_response

name = request.args["name"]
response = make_response("<h1>" + name + "</h1>")
''',
        "PY-XSS-001",
    ),
    (
        "app.js",
        '''function view(req, res) {
  const name = req.query.name;
  res.send("<h1>" + name + "</h1>");
}
''',
        "JS-XSS-001",
    ),
    (
        "App.java",
        '''String name = request.getParameter("name");
response.getWriter().write("<h1>" + name + "</h1>");
''',
        "JAVA-XSS-001",
    ),
    (
        "App.cs",
        '''var name = Request.Query["name"];
Response.Write("<h1>" + name + "</h1>");
''',
        "CS-XSS-001",
    ),
    (
        "app.go",
        '''name := r.URL.Query().Get("name")
fmt.Fprintf(w, "<h1>%s</h1>", name)
''',
        "GO-XSS-001",
    ),
    (
        "app.rb",
        '''name = params[:name]
raw("<h1>#{name}</h1>")
''',
        "RB-XSS-001",
    ),
)


@pytest.mark.parametrize(("filename", "source", "rule_id"), XSS_CASES)
def test_xss_matrix(
    tmp_path: Path,
    filename: str,
    source: str,
    rule_id: str,
) -> None:
    (tmp_path / filename).write_text(source, encoding="utf-8")

    result = scan(ScanConfig(tmp_path, offline=True, cve=False))

    matches = [item for item in result.findings if item.rule_id == rule_id]
    assert matches, [(item.rule_id, item.location.file, item.location.line) for item in result.findings]
    assert matches[0].source is not None
    assert matches[0].cwe == "CWE-79"
    assert matches[0].remediations
    assert matches[0].test_vectors


SAFE_XSS_CASES = (
    (
        "app.py",
        '''import html
from flask import request, make_response

name = html.escape(request.args["name"])
response = make_response("<h1>" + name + "</h1>")
''',
        "PY-XSS-001",
    ),
    (
        "app.js",
        '''function view(req, res) {
  const name = escapeHtml(req.query.name);
  res.send("<h1>" + name + "</h1>");
}
''',
        "JS-XSS-001",
    ),
    (
        "App.java",
        '''String name = HtmlUtils.htmlEscape(request.getParameter("name"));
response.getWriter().write("<h1>" + name + "</h1>");
''',
        "JAVA-XSS-001",
    ),
    (
        "App.cs",
        '''var name = HtmlEncoder.Default.Encode(Request.Query["name"]);
Response.Write("<h1>" + name + "</h1>");
''',
        "CS-XSS-001",
    ),
    (
        "app.go",
        '''name := html.EscapeString(r.URL.Query().Get("name"))
fmt.Fprintf(w, "<h1>%s</h1>", name)
''',
        "GO-XSS-001",
    ),
    (
        "app.rb",
        '''name = ERB::Util.html_escape(params[:name])
raw("<h1>#{name}</h1>")
''',
        "RB-XSS-001",
    ),
)


@pytest.mark.parametrize(("filename", "source", "rule_id"), SAFE_XSS_CASES)
def test_encoded_xss_flow_is_not_reported(
    tmp_path: Path,
    filename: str,
    source: str,
    rule_id: str,
) -> None:
    (tmp_path / filename).write_text(source, encoding="utf-8")

    result = scan(ScanConfig(tmp_path, offline=True, cve=False))

    assert rule_id not in {item.rule_id for item in result.findings}
