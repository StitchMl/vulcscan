from __future__ import annotations

import io
import json
import urllib.error
from pathlib import Path

from vulcscan.cve import OSVClient
from vulcscan.dependencies import scan_dependencies
from vulcscan.models import Dependency


class _Response(io.BytesIO):
    def close(self) -> None:
        super().close()


def _json_response(value: object) -> _Response:
    return _Response(json.dumps(value).encode("utf-8"))


def _by_name(items: list[Dependency], ecosystem: str, name: str) -> list[Dependency]:
    return [
        item
        for item in items
        if item.ecosystem == ecosystem and item.name.casefold() == name.casefold()
    ]


def test_lockfile_version_replaces_manifest_constraint(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        """
[project]
dependencies = ["Requests>=2.30", "only-manifest~=1.0"]
""".strip(),
        encoding="utf-8",
    )
    (tmp_path / "poetry.lock").write_text(
        """
[[package]]
name = "requests"
version = "2.32.3"

[[package]]
name = "urllib3"
version = "2.2.2"
""".strip(),
        encoding="utf-8",
    )

    dependencies, errors = scan_dependencies(tmp_path)

    requests = _by_name(dependencies, "PyPI", "requests")
    assert len(requests) == 1
    assert requests[0].version == "2.32.3"
    assert requests[0].resolved is True
    assert requests[0].direct is True
    assert requests[0].constraint == ">=2.30"
    assert requests[0].source_file == "poetry.lock"

    unresolved = _by_name(dependencies, "PyPI", "only-manifest")
    assert len(unresolved) == 1
    assert unresolved[0].version is None
    assert unresolved[0].constraint == "~=1.0"
    assert unresolved[0].resolved is False


def test_parses_resolved_versions_across_ecosystems(tmp_path: Path) -> None:
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"left-pad": "^1.0.0"}},
                    "node_modules/left-pad": {"version": "1.3.0"},
                },
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    (tmp_path / "composer.lock").write_text(
        json.dumps({"packages": [{"name": "vendor/lib", "version": "1.4.2"}]}),
        encoding="utf-8",
    )
    (tmp_path / "go.mod").write_text(
        "module example.test/app\n\nrequire golang.org/x/text v0.16.0\n",
        encoding="utf-8",
    )
    (tmp_path / "Gemfile.lock").write_text(
        """GEM
  remote: https://rubygems.org/
  specs:
    rack (3.0.9)

DEPENDENCIES
  rack
""",
        encoding="utf-8",
    )
    (tmp_path / "packages.lock.json").write_text(
        json.dumps(
            {
                "version": 1,
                "dependencies": {
                    "net8.0": {
                        "Example.Core": {
                            "type": "Direct",
                            "requested": "[4.0.0, )",
                            "resolved": "4.2.1",
                        }
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "Cargo.lock").write_text(
        """version = 3

[[package]]
name = "serde"
version = "1.0.204"
source = "registry+https://github.com/rust-lang/crates.io-index"
""",
        encoding="utf-8",
    )

    dependencies, errors = scan_dependencies(tmp_path)
    versions = {(item.ecosystem, item.name): item.version for item in dependencies}

    assert versions[("npm", "left-pad")] == "1.3.0"
    assert versions[("Composer", "vendor/lib")] == "1.4.2"
    assert versions[("Go", "golang.org/x/text")] == "v0.16.0"
    assert versions[("RubyGems", "rack")] == "3.0.9"
    assert versions[("NuGet", "Example.Core")] == "4.2.1"
    assert versions[("Cargo", "serde")] == "1.0.204"


def test_parser_failure_is_isolated_and_reported(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text("{ broken", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("flask==3.0.3\n", encoding="utf-8")

    dependencies, errors = scan_dependencies(tmp_path)

    flask = _by_name(dependencies, "PyPI", "flask")
    assert flask[0].version == "3.0.3"
    # An exact == pin is the version pip installs, so it is resolved and queryable.
    assert flask[0].resolved is True
    assert flask[0].version_source == "manifest-pin"
    assert any(error.file == "package.json" and error.phase == "dependency-parse" for error in errors)


def test_scan_can_reuse_discovered_manifest_paths(tmp_path: Path) -> None:
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("flask==3.0.3\n", encoding="utf-8")
    (tmp_path / "package.json").write_text(
        '{"dependencies":{"express":"4.19.2"}}', encoding="utf-8"
    )

    dependencies, errors = scan_dependencies(tmp_path, [requirements])

    assert [(item.ecosystem, item.name) for item in dependencies] == [("PyPI", "flask")]


def test_unlocked_manifests_preserve_constraints_and_locations(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text(
        "django==5.0.6 \\\n    --hash=sha256:deadbeef\n",
        encoding="utf-8",
    )
    (tmp_path / "pom.xml").write_text(
        """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <properties><jackson.version>2.17.1</jackson.version></properties>
  <dependencies><dependency>
    <groupId>com.fasterxml.jackson.core</groupId>
    <artifactId>jackson-databind</artifactId>
    <version>${jackson.version}</version>
  </dependency></dependencies>
</project>""",
        encoding="utf-8",
    )
    (tmp_path / "build.gradle.kts").write_text(
        'dependencies {\n  implementation(group = "org.example", name = "core", version = "1.2.3")\n}\n',
        encoding="utf-8",
    )
    (tmp_path / "app.csproj").write_text(
        '<Project><ItemGroup><PackageReference Include="Polly" Version="8.4.0" /></ItemGroup></Project>',
        encoding="utf-8",
    )
    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname="app"\nversion="0.1.0"\n[dependencies]\nregex="1.10.5"\n',
        encoding="utf-8",
    )

    dependencies, errors = scan_dependencies(tmp_path)

    django = _by_name(dependencies, "PyPI", "django")[0]
    assert (django.version, django.constraint, django.resolved, django.line) == (
        "5.0.6",
        "==5.0.6",
        True,  # an exact pin is resolved and queryable
        1,
    )
    assert django.version_source == "manifest-pin"
    jackson = _by_name(
        dependencies, "Maven", "com.fasterxml.jackson.core:jackson-databind"
    )[0]
    assert jackson.version == "2.17.1"
    assert jackson.resolved is True
    gradle = _by_name(dependencies, "Maven", "org.example:core")[0]
    assert gradle.version == "1.2.3"
    assert gradle.source_file == "build.gradle.kts"
    polly = _by_name(dependencies, "NuGet", "Polly")[0]
    assert polly.version == "8.4.0"
    assert polly.resolved is True
    regex = _by_name(dependencies, "Cargo", "regex")[0]
    assert regex.version is None
    assert regex.constraint == "1.10.5"


def test_yarn_and_pnpm_lock_syntaxes(tmp_path: Path) -> None:
    yarn = tmp_path / "yarn-project"
    yarn.mkdir()
    (yarn / "yarn.lock").write_text(
        '"@scope/widget@^2.0.0", "@scope/widget@~2.1.0":\n  version "2.1.4"\n',
        encoding="utf-8",
    )
    pnpm = tmp_path / "pnpm-project"
    pnpm.mkdir()
    (pnpm / "pnpm-lock.yaml").write_text(
        """lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      tiny-lib:
        specifier: ^3.0.0
        version: 3.2.1
packages:
  tiny-lib@3.2.1:
    resolution: {integrity: sha512-example}
  '@scope/other@4.5.6':
    resolution: {integrity: sha512-example}
""",
        encoding="utf-8",
    )

    dependencies, errors = scan_dependencies(tmp_path)

    assert _by_name(dependencies, "npm", "@scope/widget")[0].version == "2.1.4"
    tiny = _by_name(dependencies, "npm", "tiny-lib")[0]
    assert tiny.version == "3.2.1"
    assert tiny.direct is True
    assert _by_name(dependencies, "npm", "@scope/other")[0].version == "4.5.6"


def test_osv_query_uses_exact_resolved_versions_without_persistent_cache(tmp_path: Path) -> None:
    calls: list[str] = []
    advisory = {
        "id": "GHSA-test-0001",
        "aliases": ["CVE-2026-1234"],
        "summary": "Example vulnerability",
        "severity": [
            {
                "type": "CVSS_V3",
                "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            }
        ],
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "demo"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "2.0.1"},
                        ],
                    }
                ],
            }
        ],
        "references": [{"type": "ADVISORY", "url": "https://example.test/a"}],
    }

    def opener(request: object, timeout: float) -> _Response:
        calls.append(request.full_url)  # type: ignore[attr-defined]
        assert timeout == 1.0
        if request.data is None:  # type: ignore[attr-defined]
            # OSV querybatch returns ids only; details come from /v1/vulns/{id}.
            return _json_response(advisory)
        body = json.loads(request.data.decode("utf-8"))  # type: ignore[attr-defined]
        assert body == {
            "queries": [
                {"package": {"ecosystem": "PyPI", "name": "demo"}, "version": "2.0.0"}
            ]
        }
        return _json_response({"results": [{"vulns": [{"id": advisory["id"]}, {"id": advisory["id"]}]}]})

    dependency = Dependency(
        name="demo",
        version="2.0.0",
        ecosystem="PyPI",
        source_file="poetry.lock",
        line=4,
        direct=True,
        resolved=True,
    )
    client = OSVClient(offline=False, timeout=1.0, opener=opener)

    vulnerabilities = client.query([dependency, dependency])

    assert len(vulnerabilities) == 1
    vulnerability = vulnerabilities[0]
    assert vulnerability.id == "CVE-2026-1234"
    assert vulnerability.aliases == ("GHSA-test-0001",)
    assert vulnerability.fixed_versions == ("2.0.1",)
    assert vulnerability.affected_ranges == ("ECOSYSTEM: < 2.0.1",)
    assert vulnerability.severity == "CRITICAL"
    assert vulnerability.cvss == 9.8
    assert calls == [
        "https://api.osv.dev/v1/querybatch",
        "https://api.osv.dev/v1/vulns/GHSA-test-0001",
    ]
    assert list(tmp_path.iterdir()) == []

    def forbidden_opener(request: object, timeout: float) -> _Response:
        raise AssertionError("offline mode attempted network access")

    offline = OSVClient(offline=True, opener=forbidden_opener)
    assert offline.query([dependency]) == []
    assert offline.errors == []


def test_osv_fetches_id_only_details_and_retries_once(tmp_path: Path) -> None:
    calls: list[str] = []

    def opener(request: object, timeout: float) -> _Response:
        url = request.full_url  # type: ignore[attr-defined]
        calls.append(url)
        if len(calls) == 1:
            raise urllib.error.URLError("temporary")
        if url.endswith("querybatch"):
            return _json_response({"results": [{"vulns": [{"id": "OSV-2026-1"}]}]})
        return _json_response(
            {
                "id": "OSV-2026-1",
                "summary": "Detailed advisory",
                "affected": [
                    {
                        "package": {"ecosystem": "npm", "name": "widget"},
                        "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}]}],
                    }
                ],
            }
        )

    dependency = Dependency(
        "widget", "1.2.0", "npm", "package-lock.json", 8, True, True
    )
    client = OSVClient(
        offline=False,
        retries=1,
        opener=opener,
        sleep=lambda _: None,
    )

    vulnerabilities = client.query([dependency])

    assert vulnerabilities[0].id == "OSV-2026-1"
    # No severity data in the advisory: report UNKNOWN instead of inventing INFO.
    assert vulnerabilities[0].severity == "UNKNOWN"
    assert vulnerabilities[0].fixed_versions == ()
    assert vulnerabilities[0].affected_ranges == ("SEMVER: >= 1.0.0",)
    assert len(calls) == 3


def test_offline_mode_and_unresolved_constraints_make_no_request(tmp_path: Path) -> None:
    calls = 0

    def opener(request: object, timeout: float) -> _Response:
        nonlocal calls
        calls += 1
        raise AssertionError("network access was not expected")

    unresolved = Dependency(
        "demo", None, "PyPI", "requirements.txt", 1, True, False, ">=1"
    )
    exact_but_unresolved = Dependency(
        "demo", "1.2.3", "PyPI", "requirements.txt", 1, True, False, "==1.2.3"
    )

    assert OSVClient(offline=False, opener=opener).query(
        [unresolved, exact_but_unresolved]
    ) == []
    assert OSVClient(offline=True, opener=opener).query(
        [Dependency("demo", "1.2.3", "PyPI", "poetry.lock", 1, True, True)]
    ) == []
    assert calls == 0


def test_osv_client_blocks_non_allowlisted_network_endpoint(tmp_path: Path) -> None:
    calls: list[str] = []

    def opener(request: object, timeout: float) -> _Response:
        calls.append(request.full_url)  # type: ignore[attr-defined]
        return _json_response({})

    client = OSVClient(offline=False, opener=opener)
    result = client._request_json("https://example.com/v1/querybatch", {"queries": []})

    assert result is None
    assert calls == []
    assert client.errors == [
        "blocked non-allowlisted network endpoint: https://example.com/v1/querybatch"
    ]


def test_osv_client_rejects_osv_lookalike_hosts_and_query_strings(tmp_path: Path) -> None:
    calls: list[str] = []

    def opener(request: object, timeout: float) -> _Response:
        calls.append(request.full_url)  # type: ignore[attr-defined]
        return _json_response({})

    client = OSVClient(offline=False, opener=opener)
    blocked = (
        "https://api.osv.dev.example.com/v1/querybatch",
        "http://api.osv.dev/v1/querybatch",
        "https://api.osv.dev:444/v1/querybatch",
        "https://api.osv.dev/v1/querybatch?redirect=https://example.com",
        "https://api.osv.dev/v1/vulns/GHSA-test%0A",
    )

    for url in blocked:
        assert client._request_json(url, None) is None

    assert calls == []
    assert len(client.errors) == len(blocked)


def test_osv_allowlist_accepts_explicit_https_port(tmp_path: Path) -> None:
    calls: list[str] = []

    def opener(request: object, timeout: float) -> _Response:
        calls.append(request.full_url)  # type: ignore[attr-defined]
        return _json_response({})

    client = OSVClient(offline=False, opener=opener)
    assert client._request_json("https://api.osv.dev:443/v1/querybatch", None) == {}
    assert calls == ["https://api.osv.dev:443/v1/querybatch"]
