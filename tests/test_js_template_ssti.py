from __future__ import annotations

from pathlib import Path

from vulcscan.scanner import scan_path


def _ssti(root: Path, code: str, ext: str = ".js", **opts):
    (root / ("app" + ext)).write_text(code, encoding="utf-8")
    return [
        f for f in scan_path(root, cve=False, **opts).findings
        if f.rule_id == "JS-SSTI-001"
    ]


def test_ejs_render_http_template_source(tmp_path: Path) -> None:
    found = _ssti(tmp_path,
        "function handler(req) {\n"
        "  return ejs.render(req.body.template, { name: 'test' });\n"
        "}\n", remote_only=True)
    assert len(found) == 1
    assert found[0].cwe == "CWE-1336"
    assert found[0].source is not None
    assert found[0].location.line == 2
    assert [step.kind for step in found[0].flow] == ["SOURCE", "SINK"]
    assert found[0].test_vectors
    assert not any(rem.machine_applicable for rem in found[0].remediations)


def test_pug_compile_with_local_assignment(tmp_path: Path) -> None:
    found = _ssti(tmp_path,
        "function handler(req) {\n"
        "  const template = req.query.template;\n"
        "  return pug.compile(template);\n"
        "}\n", ".ts")
    assert len(found) == 1


def test_handlebars_compile_request_string(tmp_path: Path) -> None:
    found = _ssti(tmp_path,
        "function handler(req) {\n"
        "  return Handlebars.compile(req.body.source);\n"
        "}\n")
    assert len(found) == 1


def test_nunjucks_render_string_request_content(tmp_path: Path) -> None:
    found = _ssti(tmp_path,
        "function handler(req) {\n"
        "  return nunjucks.renderString(req.body.message, {});\n"
        "}\n")
    assert len(found) == 1


def test_trusted_template_and_untrusted_context_are_safe(tmp_path: Path) -> None:
    found = _ssti(tmp_path,
        "function handler(req) {\n"
        "  return ejs.render('<%= name %>', { name: req.query.name });\n"
        "}\n")
    assert found == []


def test_rendering_fixed_template_file_is_safe(tmp_path: Path) -> None:
    found = _ssti(tmp_path,
        "function handler(req, res) {\n"
        "  res.render('profile', { user: req.body.username });\n"
        "}\n")
    assert found == []


def test_templates_from_config_and_unknown_local_data_not_guessed(tmp_path: Path) -> None:
    found = _ssti(tmp_path,
        "function handler(req) {\n"
        "  const template = 'Hello {{name}}';\n"
        "  return Handlebars.compile(template);\n"
        "}\n")
    assert found == []


def test_compilation_inside_comment_is_not_sink(tmp_path: Path) -> None:
    found = _ssti(tmp_path,
        "function handler(req) {\n"
        "  // ejs.render(req.body.template)\n"
        "  return 'safe';\n"
        "}\n")
    assert found == []
