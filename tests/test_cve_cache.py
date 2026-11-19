from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulcscan.cli import build_parser
from vulcscan.cve import OSVClient
from vulcscan.models import Dependency
from vulcscan.scanner import scan_path


def _dependency(name: str = "examplepackage", version: str = "1.0.0") -> Dependency:
    return Dependency(
        name=name, version=version, ecosystem="pypi",
        source_file="requirements.txt", line=1,
        resolved=True, version_source="manifest-pin",
    )


def _advisory() -> dict:
    return {
        "id": "OSV-2026-SYNTHETIC",
        "aliases": ["CVE-2026-12345"],
        "summary": "Synthetic vulnerability fixture",
        "affected": [{
            "package": {"ecosystem": "PyPI", "name": "examplepackage"},
            "ranges": [{"type": "ECOSYSTEM", "events": [
                {"introduced": "0"}, {"fixed": "2.0.0"},
            ]}],
        }],
    }


class _SuccessfulLive(OSVClient):
    def _query_batch(self, dependencies):
        return [["OSV-2026-SYNTHETIC"] if dep.name == "examplepackage" else [] for dep in dependencies]

    def _get_advisory(self, advisory_id):
        assert advisory_id == "OSV-2026-SYNTHETIC"
        return _advisory()


def _forbid_network(*args, **kwargs):
    raise AssertionError("cached OSV scan must not make a network request")


def test_live_cache_written_then_replayed_offline(tmp_path: Path) -> None:
    path = tmp_path / "offline-cache.json"
    live = _SuccessfulLive(offline=False, cache_path=path, opener=_forbid_network)
    live_findings = live.query([_dependency()])
    assert not live.errors
    assert path.is_file()
    saved = json.loads(path.read_text("utf-8"))
    assert saved["format"] == "vulcscan-osv-v1"
    assert saved["entries"][0]["version"] == "1.0.0"
    offline = OSVClient(offline=True, cache_path=path, opener=_forbid_network)
    cached_findings = offline.query([_dependency()])
    assert cached_findings == live_findings
    assert len(cached_findings) == 1


def test_cache_has_exact_package_version_scope(tmp_path: Path) -> None:
    path = tmp_path / "cache.json"
    _SuccessfulLive(cache_path=path, opener=_forbid_network).query([_dependency()])
    client = OSVClient(offline=True, cache_path=path, opener=_forbid_network)
    assert client.query([_dependency(version="9.0.0")]) == []
    assert client.query([_dependency(name="otherpackage")]) == []


def test_empty_advisory_results_still_cache_complete_query(tmp_path: Path) -> None:
    path = tmp_path / "cache.json"
    client = _SuccessfulLive(cache_path=path, opener=_forbid_network)
    assert client.query([_dependency(name="unaffected")]) == []
    document = json.loads(path.read_text("utf-8"))
    assert document["entries"][0]["advisories"] == []


def test_partial_query_does_not_overwrite_existing_cache(tmp_path: Path) -> None:
    path = tmp_path / "cache.json"
    _SuccessfulLive(cache_path=path, opener=_forbid_network).query([_dependency()])
    original = path.read_bytes()

    class _FailingLive(_SuccessfulLive):
        def _query_batch(self, dependencies):
            self.errors.append("OSV query failed")
            return None

    failing = _FailingLive(cache_path=path, opener=_forbid_network)
    assert failing.query([_dependency()]) == []
    assert failing.errors
    assert path.read_bytes() == original


def test_partial_advisory_does_not_overwrite_existing_cache(tmp_path: Path) -> None:
    path = tmp_path / "cache.json"
    _SuccessfulLive(cache_path=path, opener=_forbid_network).query([_dependency()])
    original = path.read_bytes()

    class _FailingLive(_SuccessfulLive):
        def _get_advisory(self, advisory_id):
            self.errors.append("synthetic timeout")
            return None

    failing = _FailingLive(cache_path=path, opener=_forbid_network)
    assert failing.errors == []
    assert failing.query([_dependency()]) == []
    assert failing.errors
    assert path.read_bytes() == original


def test_invalid_offline_cache_returns_error_without_network(tmp_path: Path) -> None:
    path = tmp_path / "cache.json"
    path.write_text("{bad-json", encoding="utf-8")
    client = OSVClient(offline=True, cache_path=path, opener=_forbid_network)
    assert client.query([_dependency()]) == []
    assert client.errors


def test_cache_symlink_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "cache.json"
    destination = tmp_path / "destination.json"
    destination.write_text("protected", encoding="utf-8")
    try:
        path.symlink_to(destination)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation unavailable")
    writer = _SuccessfulLive(cache_path=path, opener=_forbid_network)
    writer.query([_dependency()])
    assert writer.errors
    assert destination.read_text("utf-8") == "protected"


def test_cli_cache_option_and_defaults(tmp_path: Path) -> None:
    parser = build_parser()
    assert parser.parse_args([str(tmp_path)]).cve_cache is None
    supplied = parser.parse_args([str(tmp_path), "--cve-cache", str(tmp_path / "cache.json")])
    assert supplied.cve_cache == tmp_path / "cache.json"


def test_scanner_uses_cache_offline_with_report_network_disabled(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("examplepackage==1.0.0\n", encoding="utf-8")
    cache = tmp_path / "cache.json"
    _SuccessfulLive(cache_path=cache, opener=_forbid_network).query([_dependency()])
    report = scan_path(tmp_path, offline=True, cve=True, cve_cache=cache)
    assert report.metadata["network_access"] == "DISABLED"
    assert any(v.id == "CVE-2026-12345" for v in report.dependency_vulnerabilities)
