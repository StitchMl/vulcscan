from __future__ import annotations

import json
from pathlib import Path

from vulcscan.cli import build_parser
from vulcscan.cve import OSVClient
from vulcscan.models import Dependency
from vulcscan.scanner import scan_path


def _dependency(version: str = "1.0.0", ecosystem: str = "pypi") -> Dependency:
    return Dependency(
        name="examplepackage", version=version, ecosystem=ecosystem,
        source_file="requirements.txt", line=1,
        resolved=True, version_source="manifest-pin",
    )


def _advisory() -> dict:
    return {
        "id": "OSV-2026-EXAMPLE",
        "aliases": ["CVE-2026-12345"],
        "summary": "Synthetic test advisory",
        "affected": [{
            "package": {"ecosystem": "PyPI", "name": "examplepackage"},
            "ranges": [{"type": "ECOSYSTEM", "events": [
                {"introduced": "0"}, {"fixed": "2.0.0"},
            ]}],
        }],
    }


def _snapshot(path: Path, **overrides) -> None:
    document = {
        "format": "vulcscan-osv-v1",
        "entries": [{
            "ecosystem": "PyPI",
            "name": "examplepackage",
            "version": "1.0.0",
            "advisories": [_advisory()],
        }],
    }
    document.update(overrides)
    path.write_text(json.dumps(document), encoding="utf-8")


def _forbid_network(*args, **kwargs):
    raise AssertionError("local OSV DB may not open the network")


def test_local_database_exact_version_match_offline(tmp_path: Path) -> None:
    db = tmp_path / "snapshot.json"
    _snapshot(db)
    client = OSVClient(offline=True, local_db=db, opener=_forbid_network)
    found = client.query([_dependency()])
    assert not client.errors
    assert len(found) == 1
    assert found[0].id == "CVE-2026-12345"
    assert found[0].fixed_versions == ("2.0.0",)
    assert found[0].source == "OSV"


def test_no_match_when_dependency_version_is_not_listed(tmp_path: Path) -> None:
    db = tmp_path / "snapshot.json"
    _snapshot(db)
    client = OSVClient(offline=True, local_db=db, opener=_forbid_network)
    assert not client.query([_dependency("3.0.0")])


def test_advisory_range_must_include_version(tmp_path: Path) -> None:
    db = tmp_path / "snapshot.json"
    advisory = _advisory()
    advisory["affected"][0]["ranges"][0]["events"] = [
        {"introduced": "2.0.0"}, {"fixed": "3.0.0"},
    ]
    _snapshot(db, entries=[{
        "ecosystem": "PyPI",
        "name": "examplepackage",
        "version": "1.0.0",
        "advisories": [advisory],
    }])
    client = OSVClient(offline=True, local_db=db, opener=_forbid_network)
    assert not client.query([_dependency()])


def test_unmatched_ecosystem_is_not_confused(tmp_path: Path) -> None:
    db = tmp_path / "snapshot.json"
    _snapshot(db)
    client = OSVClient(offline=True, local_db=db, opener=_forbid_network)
    assert not client.query([_dependency(ecosystem="npm")])


def test_invalid_and_truncated_snapshot_reports_error(tmp_path: Path) -> None:
    db = tmp_path / "snapshot.json"
    db.write_text("{", encoding="utf-8")
    client = OSVClient(offline=True, local_db=db, opener=_forbid_network)
    assert client.query([_dependency()]) == []
    assert client.errors


def test_nonexistent_snapshot_is_not_downloaded(tmp_path: Path) -> None:
    client = OSVClient(offline=True, local_db=tmp_path / "missing.json", opener=_forbid_network)
    assert client.query([_dependency()]) == []
    assert any("snapshot" in msg for msg in client.errors)


def test_no_database_default_stays_offline() -> None:
    client = OSVClient(offline=True, opener=_forbid_network)
    assert client.query([_dependency()]) == []


def test_cve_db_cli_option_is_explicit(tmp_path: Path) -> None:
    parser = build_parser()
    assert parser.parse_args([str(tmp_path)]).cve_db is None
    args = parser.parse_args([str(tmp_path), "--cve-db", str(tmp_path / "snap.json")])
    assert args.cve_db == tmp_path / "snap.json"


def test_snapshot_in_scan_config_preserves_network_disabled(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("examplepackage==1.0.0\n", encoding="utf-8")
    db = tmp_path / "osv-snapshot.json"
    _snapshot(db)
    result = scan_path(tmp_path, cve=True, offline=True, cve_db=db)
    assert result.metadata["network_access"] == "DISABLED"
    assert any(v.id == "CVE-2026-12345" for v in result.dependency_vulnerabilities)
