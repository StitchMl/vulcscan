from __future__ import annotations

from pathlib import Path

from vulcscan.models import Confidence
from vulcscan.scanner import scan_path


def _scan(tmp_path: Path, source: str, suffix: str = "js"):
    (tmp_path / ("app." + suffix)).write_text(source, encoding="utf-8")
    return [f for f in scan_path(tmp_path, cve=False).findings if f.rule_id == "JS-NOSQL-001"]


def test_mongoose_model_direct_request_body(tmp_path: Path) -> None:
    found = _scan(tmp_path,
        "function list(req, res) {\n"
        "  return User.find(req.body);\n"
        "}\n",
    )
    assert len(found) == 1
    assert found[0].cwe == "CWE-943"
    assert found[0].confidence == Confidence.MEDIUM
    assert found[0].source is not None
    assert found[0].flow[0].kind == "SOURCE"
    assert found[0].test_vectors
    assert not any(rem.machine_applicable for rem in found[0].remediations)


def test_mongodb_collection_with_assigned_http_object(tmp_path: Path) -> None:
    found = _scan(tmp_path,
        "function query(req) {\n"
        "  const filter = req.query;\n"
        "  return collection.findOne(filter);\n"
        "}\n",
        "ts",
    )
    assert len(found) == 1
    assert found[0].location.line == 3


def test_http_object_in_update_query(tmp_path: Path) -> None:
    found = _scan(tmp_path,
        "function update(req) {\n"
        "  db.collection.updateOne(req.body, { active: true });\n"
        "}\n",
    )
    assert len(found) == 1


def test_literal_schema_filter_is_not_flagged(tmp_path: Path) -> None:
    found = _scan(tmp_path,
        "function lookup(req) {\n"
        "  return User.find({ _id: req.params.id });\n"
        "}\n",
    )
    assert not found


def test_field_by_field_explicit_filter_is_not_flagged(tmp_path: Path) -> None:
    found = _scan(tmp_path,
        "function lookup(req) {\n"
        "  return collection.find({ status: 'active', id: req.query.id });\n"
        "}\n",
    )
    assert not found


def test_non_db_collection_method_is_not_flagged(tmp_path: Path) -> None:
    found = _scan(tmp_path,
        "function handle(req) {\n"
        "  return items.find(req.body);\n"
        "}\n",
    )
    assert not found


def test_locally_fixed_and_numeric_filter_are_not_flagged(tmp_path: Path) -> None:
    found = _scan(tmp_path,
        "function handle(req) {\n"
        "  const filter = { active: true };\n"
        "  User.find(filter);\n"
        "  User.find(Number(req.query.id));\n"
        "}\n",
    )
    assert not found
