from __future__ import annotations

from pathlib import Path

from vulcscan.models import Confidence
from vulcscan.scanner import scan_path


def _find(root: Path, code: str):
    (root / "template.php").write_text(code, encoding="utf-8")
    return [
        item for item in scan_path(root, cve=False).findings
        if item.rule_id == "PHP-SSTI-001"
    ]


def test_direct_twig_template_source_from_post(tmp_path: Path) -> None:
    found = _find(tmp_path,
        "<?php\n"
        '$result = $twig->createTemplate($_POST["template"])->render([]);\n',
    )
    assert len(found) == 1
    assert found[0].location.line == 2
    assert found[0].cwe == "CWE-1336"
    assert found[0].confidence == Confidence.MEDIUM
    assert found[0].test_vectors
    assert all(not fix.machine_applicable for fix in found[0].remediations)


def test_intermediate_request_variable_flows_into_template_source(tmp_path: Path) -> None:
    found = _find(tmp_path,
        "<?php\n"
        '$tpl = $_GET["source"];\n'
        "$twig->createTemplate($tpl);\n",
    )
    assert len(found) == 1
    assert found[0].location.line == 3


def test_fixed_template_and_user_context_safe(tmp_path: Path) -> None:
    found = _find(tmp_path,
        "<?php\n"
        '$twig->render("profile.html.twig", ["name" => $_POST["name"]]);\n'
        '$twig->createTemplate("Hello {{ name }}")->render(["name" => $_POST["name"]]);\n',
    )
    assert not found


def test_sanitized_or_overwritten_template_value_is_not_guessed(tmp_path: Path) -> None:
    found = _find(tmp_path,
        "<?php\n"
        '$tpl = $_POST["template"];\n'
        '$tpl = "fixed template";\n'
        '$twig->createTemplate($tpl);\n',
    )
    assert not found


def test_unrelated_create_template_object_not_flagged(tmp_path: Path) -> None:
    found = _find(tmp_path,
        "<?php\n"
        '$builder->createTemplate($_POST["template"]);\n',
    )
    assert not found


def test_comments_and_quoted_source_do_not_trigger(tmp_path: Path) -> None:
    found = _find(tmp_path,
        "<?php\n"
        '// $twig->createTemplate($_POST["template"]);\n'
        '/* $twig->createTemplate($_POST["template"]); */\n'
        """$text = '$twig->createTemplate($_POST["template"])';\n""",
    )
    assert not found


def test_php_route_requires_explicit_http_source(tmp_path: Path) -> None:
    found = _find(tmp_path,
        "<?php\n"
        '$template = getTrustedTemplate();\n'
        '$twig->createTemplate($template);\n',
    )
    assert not found
