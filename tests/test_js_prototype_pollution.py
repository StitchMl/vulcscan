from __future__ import annotations

from pathlib import Path

from vulcscan.models import Confidence
from vulcscan.scanner import scan_path


def _found(root: Path, source: str, suffix: str = "js"):
    (root / ("app." + suffix)).write_text(source, encoding="utf-8")
    return [f for f in scan_path(root, cve=False).findings if f.rule_id == "JS-PROTOTYPE-001"]


def test_untrusted_request_body_object_assign(tmp_path: Path) -> None:
    found = _found(tmp_path,
        "function update(req) {\n"
        "  Object.assign(config, req.body);\n"
        "}\n",
    )
    assert len(found) == 1
    assert found[0].cwe == "CWE-1321"
    assert found[0].confidence == Confidence.MEDIUM
    assert found[0].source is not None
    assert found[0].test_vectors
    assert not any(r.machine_applicable for r in found[0].remediations)


def test_lodash_merge_with_assigned_request_query(tmp_path: Path) -> None:
    found = _found(tmp_path,
        "function update(req) {\n"
        "  const payload = req.query;\n"
        "  _.merge(state, payload);\n"
        "}\n",
        "ts",
    )
    assert len(found) == 1
    assert found[0].location.line == 3


def test_default_values_merging_http_input(tmp_path: Path) -> None:
    found = _found(tmp_path,
        "function handler(req) {\n"
        "  lodash.defaultsDeep(config, req.body);\n"
        "}\n",
    )
    assert len(found) == 1


def test_explicit_field_updates_are_not_reported(tmp_path: Path) -> None:
    found = _found(tmp_path,
        "function handler(req) {\n"
        "  Object.assign(config, { theme: req.body.theme });\n"
        "}\n",
    )
    assert not found


def test_fixed_default_merge_is_not_reported(tmp_path: Path) -> None:
    found = _found(tmp_path,
        "function handler(req) {\n"
        "  const overrides = { theme: 'dark' };\n"
        "  Object.assign(config, overrides);\n"
        "}\n",
    )
    assert not found


def test_array_assign_and_unrelated_method_are_not_reported(tmp_path: Path) -> None:
    found = _found(tmp_path,
        "function handler(req) {\n"
        "  settings.update(req.body);\n"
        "  custom.merge(config, req.query);\n"
        "}\n",
    )
    assert not found


def test_numeric_conversions_are_not_reported(tmp_path: Path) -> None:
    found = _found(tmp_path,
        "function handler(req) {\n"
        "  Object.assign(config, Number(req.query.count));\n"
        "}\n",
    )
    assert not found
