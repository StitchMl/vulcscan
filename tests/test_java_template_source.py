from __future__ import annotations

from pathlib import Path

from vulcscan.scanner import scan_path


def _issues(root: Path, source: str):
    (root / "Render.java").write_text(source, encoding="utf-8")
    return [f for f in scan_path(root, cve=False).findings if f.rule_id == "JAVA-SSTI-001"]


def test_freemarker_template_constructed_from_http_parameter(tmp_path: Path):
    findings = _issues(tmp_path,
        'class Render {\n'
        '  void render(Request request, Configuration cfg) {\n'
        '    Template template = new Template("input", new StringReader(request.getParameter("template")), cfg);\n'
        '  }\n'
        '}\n',
    )
    assert len(findings) == 1
    assert findings[0].cwe == "CWE-1336"
    assert findings[0].source is not None
    assert findings[0].test_vectors
    assert not any(fix.machine_applicable for fix in findings[0].remediations)


def test_java_template_source_is_available_to_remote_only_scan(tmp_path: Path):
    (tmp_path / "Render.java").write_text(
        'class Render {\n'
        '  void render(Request request, Configuration cfg) {\n'
        '    Template template = new Template("input", new StringReader(request.getParameter("template")), cfg);\n'
        '  }\n'
        '}\n',
        encoding="utf-8",
    )
    findings = scan_path(tmp_path, cve=False, remote_only=True).findings
    assert any(finding.rule_id == "JAVA-SSTI-001" for finding in findings)


def test_freemarker_local_alias(tmp_path: Path):
    findings = _issues(tmp_path,
        'class Render {\n'
        '  void render(Request request, Configuration cfg) {\n'
        '    String templateText = request.getParameter("template");\n'
        '    Template template = new Template("input", new StringReader(templateText), cfg);\n'
        '  }\n'
        '}\n',
    )
    assert len(findings) == 1


def test_thymeleaf_string_resolver_http_template(tmp_path: Path):
    findings = _issues(tmp_path,
        'class Render {\n'
        '  void render(Request request) {\n'
        '    StringTemplateResolver resolver = new StringTemplateResolver();\n'
        '    engine.process(request.getParameter("template"), context);\n'
        '  }\n'
        '}\n',
    )
    assert len(findings) == 1


def test_freemarker_trusted_template_context_safe(tmp_path: Path):
    assert not _issues(tmp_path,
        'class Render {\n'
        '  void render(Request request, Configuration cfg) {\n'
        '    Template template = cfg.getTemplate("profile.ftl");\n'
        '    template.process(Map.of("name", request.getParameter("name")), writer);\n'
        '  }\n'
        '}\n',
    )


def test_thymeleaf_without_string_resolver_safe(tmp_path: Path):
    assert not _issues(tmp_path,
        'class Render {\n'
        '  void render(Request request) {\n'
        '    engine.process(request.getParameter("name"), context);\n'
        '  }\n'
        '}\n',
    )


def test_local_value_overwrite_safe(tmp_path: Path):
    assert not _issues(tmp_path,
        'class Render {\n'
        '  void render(Request request, Configuration cfg) {\n'
        '    String templateText = request.getParameter("template");\n'
        '    templateText = "known";\n'
        '    Template template = new Template("input", new StringReader(templateText), cfg);\n'
        '  }\n'
        '}\n',
    )


def test_comments_are_not_compilation_sinks(tmp_path: Path):
    assert not _issues(tmp_path,
        'class Render {\n'
        '  void render(Request request) {\n'
        '    // new Template("input", new StringReader(request.getParameter("template")), cfg);\n'
        '  }\n'
        '}\n',
    )
