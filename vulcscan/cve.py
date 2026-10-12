"""OSV client: the only module of vulcscan that opens network connections.

It sends package ecosystem, name and exact version to two fixed OSV endpoints
and reads structured advisories back. Every request URL passes
:func:`network_url_allowed` first; redirects and proxies are disabled, and
certificate verification uses the platform trust store.
"""

from __future__ import annotations

import json
import math
import os
import re
import socket
import ssl
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import replace
from pathlib import Path
from typing import Any

from .dependencies import canonical_name
from .models import Dependency, Vulnerability
from .versions import compare, sort_versions

OSV_HOST = "api.osv.dev"
OSV_BATCH_URL = f"https://{OSV_HOST}/v1/querybatch"
OSV_VULNERABILITY_URL = f"https://{OSV_HOST}/v1/vulns/"
_ADVISORY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{1,127}$")
_CACHE_SCHEMA = 2
_DEFAULT_CACHE_TTL = 24 * 60 * 60
_MAX_RESPONSE_BYTES = 16 * 1024 * 1024
_BATCH_SIZE = 100
_MAX_PAGES = 10
_RETRYABLE_HTTP_CODES = {429, 500, 502, 503, 504}
_OSV_ECOSYSTEMS = {
    "cargo": "crates.io",
    "composer": "Packagist",
    "go": "Go",
    "maven": "Maven",
    "npm": "npm",
    "nuget": "NuGet",
    "pypi": "PyPI",
    "rubygems": "RubyGems",
}


class _RejectRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001 - urllib signature
        raise urllib.error.HTTPError(req.full_url, code, f"redirect to {newurl!r} refused", headers, fp)


def _default_opener() -> Callable[..., Any]:
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _RejectRedirect(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
    )
    return opener.open


def default_cache_path() -> Path:
    """Per-user cache file; never a shared temporary directory."""
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    else:
        base = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    return base / "vulcscan" / "osv-cache.json"


def network_url_allowed(url: str) -> bool:
    """True only for HTTPS requests to the two OSV API paths this client uses."""
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except ValueError:
        return False
    if parsed.scheme != "https" or parsed.hostname != OSV_HOST:
        return False
    if port not in (None, 443) or parsed.username is not None or parsed.password is not None:
        return False
    if parsed.netloc not in {OSV_HOST, f"{OSV_HOST}:443"}:
        return False
    if parsed.query or parsed.fragment:
        return False
    if parsed.path == "/v1/querybatch":
        return True
    prefix = "/v1/vulns/"
    return parsed.path.startswith(prefix) and bool(_ADVISORY_ID.fullmatch(urllib.parse.unquote(parsed.path[len(prefix) :])))


class OSVClient:
    """Deterministic client for OSV's structured vulnerability API."""

    def __init__(
        self,
        cache_path: Path | None = None,
        offline: bool = False,
        *,
        timeout: float = 8.0,
        retries: int = 1,
        cache_ttl: int = _DEFAULT_CACHE_TTL,
        opener: Callable[..., Any] | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.cache_path = Path(cache_path) if cache_path is not None else default_cache_path()
        self.offline = bool(offline)
        self.timeout = max(0.1, float(timeout))
        self.retries = max(0, min(int(retries), 3))
        self.cache_ttl = max(0, int(cache_ttl))
        self._opener = opener
        self._sleep = sleep
        self.errors: list[str] = []

    def query(self, dependencies: Iterable[Dependency]) -> list[Vulnerability]:
        self.errors.clear()
        selected = self._queryable(dependencies)
        if not selected:
            return []
        cache = self._load_cache()
        query_cache = _dict(cache.get("queries"))
        advisory_cache = _dict(cache.get("advisories"))
        changed = False
        now = time.time()

        ids_by_key: dict[str, list[str]] = {}
        missing: list[tuple[str, Dependency]] = []
        for key, dependency in selected.items():
            cached = _dict(query_cache.get(key))
            if cached and isinstance(cached.get("ids"), list) and (self.offline or _fresh(cached, now, self.cache_ttl)):
                ids_by_key[key] = [str(item) for item in cached["ids"]]
            else:
                missing.append((key, dependency))
        if missing and not self.offline:
            for chunk in _chunks(missing, _BATCH_SIZE):
                found = self._query_batch([dependency for _, dependency in chunk])
                if found is None:
                    continue
                for (key, _), ids in zip(chunk, found):
                    ids_by_key[key] = ids
                    query_cache[key] = {"stored_at": now, "ids": ids}
                    changed = True

        advisories: dict[str, dict[str, Any]] = {}
        for advisory_id in sorted({item for ids in ids_by_key.values() for item in ids}):
            cached = _dict(advisory_cache.get(advisory_id))
            data = _dict(cached.get("data"))
            if data and (self.offline or _fresh(cached, now, self.cache_ttl)):
                advisories[advisory_id] = data
                continue
            if self.offline:
                self.errors.append(f"OSV advisory {advisory_id} is not cached; offline mode makes no request")
                continue
            fetched = self._get_advisory(advisory_id)
            if fetched is not None:
                advisories[advisory_id] = fetched
                advisory_cache[advisory_id] = {"stored_at": now, "data": fetched}
                changed = True

        if changed and not self.offline:
            self._save_cache({"schema": _CACHE_SCHEMA, "queries": query_cache, "advisories": advisory_cache})

        vulnerabilities: list[Vulnerability] = []
        for key, dependency in selected.items():
            for advisory_id in ids_by_key.get(key, []):
                advisory = advisories.get(advisory_id)
                if advisory is None:
                    continue
                vulnerabilities.append(to_vulnerability(dependency, advisory))
        return _deduplicate(vulnerabilities)

    def _queryable(self, dependencies: Iterable[Dependency]) -> dict[str, Dependency]:
        selected: dict[str, Dependency] = {}
        for dependency in dependencies:
            ecosystem = osv_ecosystem(dependency.ecosystem)
            if not dependency.resolved or not dependency.version or ecosystem is None:
                continue
            key = json.dumps([ecosystem, dependency.name, dependency.version], separators=(",", ":"), ensure_ascii=False)
            current = selected.get(key)
            if current is None or _dependency_order(dependency) < _dependency_order(current):
                selected[key] = dependency
        return dict(sorted(selected.items()))

    def _query_batch(self, dependencies: list[Dependency]) -> list[list[str]] | None:
        queries = [
            {"package": {"ecosystem": osv_ecosystem(item.ecosystem), "name": item.name}, "version": item.version}
            for item in dependencies
        ]
        response = self._request_json(OSV_BATCH_URL, {"queries": queries})
        if response is None:
            return None
        results = response.get("results")
        if not isinstance(results, list) or len(results) != len(queries):
            self.errors.append("OSV querybatch returned a malformed results list")
            return None
        found: list[list[str]] = []
        for query, result in zip(queries, results):
            ids = _ids(_dict(result))
            token = _dict(result).get("next_page_token")
            pages = 1
            while isinstance(token, str) and token and pages < _MAX_PAGES:
                page = self._request_json(OSV_BATCH_URL, {"queries": [{**query, "page_token": token}]})
                page_results = page.get("results") if page else None
                if not isinstance(page_results, list) or not page_results:
                    break
                ids.extend(_ids(_dict(page_results[0])))
                token = _dict(page_results[0]).get("next_page_token")
                pages += 1
            found.append(sorted(set(ids)))
        return found

    def _get_advisory(self, advisory_id: str) -> dict[str, Any] | None:
        if not _ADVISORY_ID.fullmatch(advisory_id):
            self.errors.append(f"OSV returned an invalid advisory id: {advisory_id!r}")
            return None
        return self._request_json(OSV_VULNERABILITY_URL + urllib.parse.quote(advisory_id, safe=""), None)

    def _request_json(self, url: str, payload: dict[str, Any] | None) -> dict[str, Any] | None:
        if self.offline:
            return None
        if not network_url_allowed(url):
            self.errors.append(f"blocked non-allowlisted network endpoint: {url}")
            return None
        data = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
        headers = {"Accept": "application/json", "User-Agent": "vulcscan (deterministic SAST)"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=data, headers=headers, method="POST" if data is not None else "GET")
        opener = self._opener or _default_opener()
        for attempt in range(self.retries + 1):
            try:
                response = opener(request, timeout=self.timeout)
                try:
                    final_url = getattr(response, "geturl", lambda: url)()
                    if final_url != url and not network_url_allowed(final_url):
                        raise ValueError(f"response came from a non-allowlisted URL {final_url}")
                    body = response.read(_MAX_RESPONSE_BYTES + 1)
                finally:
                    close = getattr(response, "close", None)
                    if callable(close):
                        close()
                if len(body) > _MAX_RESPONSE_BYTES:
                    raise ValueError("OSV response exceeds size limit")
                decoded = json.loads(body.decode("utf-8"))
                if not isinstance(decoded, dict):
                    raise ValueError("OSV response root is not an object")
                return decoded
            except urllib.error.HTTPError as exc:
                retryable = exc.code in _RETRYABLE_HTTP_CODES
                message = f"OSV HTTP {exc.code} for {url}"
            except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError) as exc:
                retryable = True
                message = f"OSV network error for {url}: {exc}"
            except (UnicodeError, ValueError, OSError) as exc:
                retryable = False
                message = f"OSV invalid response for {url}: {exc}"
            if attempt >= self.retries or not retryable:
                self.errors.append(message)
                return None
            self._sleep(min(0.25 * (2**attempt), 1.0))
        return None

    def _load_cache(self) -> dict[str, Any]:
        empty = {"schema": _CACHE_SCHEMA, "queries": {}, "advisories": {}}
        try:
            if not self.cache_path.is_file():
                return empty
            raw = self.cache_path.read_bytes()
            if len(raw) > 8 * _MAX_RESPONSE_BYTES:
                raise ValueError("cache exceeds size limit")
            cache = json.loads(raw.decode("utf-8"))
            if not isinstance(cache, dict) or cache.get("schema") != _CACHE_SCHEMA:
                return empty  # an older or foreign cache format is ignored
            return cache
        except (OSError, UnicodeError, ValueError) as exc:
            self.errors.append(f"OSV cache read failed: {exc}")
            return empty

    def _save_cache(self, cache: dict[str, Any]) -> None:
        temp_path: Path | None = None
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            encoded = json.dumps(cache, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            handle = tempfile.NamedTemporaryFile(
                mode="wb", prefix=self.cache_path.name + ".", suffix=".tmp", dir=self.cache_path.parent, delete=False
            )
            temp_path = Path(handle.name)
            with handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_path, self.cache_path)
        except OSError as exc:
            self.errors.append(f"OSV cache write failed: {exc}")
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)


def osv_ecosystem(ecosystem: str) -> str | None:
    return _OSV_ECOSYSTEMS.get(ecosystem.casefold())


def to_vulnerability(dependency: Dependency, advisory: dict[str, Any]) -> Vulnerability:
    raw_id = str(advisory.get("id", "OSV-UNKNOWN"))
    aliases = {str(alias) for alias in advisory.get("aliases", []) if isinstance(alias, str)}
    cve_ids = sorted(alias for alias in aliases if alias.upper().startswith("CVE-"))
    identifier = cve_ids[0] if cve_ids else raw_id
    affected = matching_affected(advisory, dependency)
    fixed, note = applicable_fixed_versions(affected, dependency)
    severity, cvss = _severity(advisory, affected)
    return Vulnerability(
        id=identifier,
        package=dependency.name,
        installed_version=dependency.version or "",
        ecosystem=dependency.ecosystem,
        summary=_summary(advisory, raw_id),
        severity=severity,
        aliases=tuple(sorted(({raw_id} | aliases) - {identifier})),
        affected_ranges=tuple(_affected_ranges(affected)),
        fixed_versions=fixed,
        references=tuple(
            sorted({str(item.get("url")) for item in advisory.get("references", []) if isinstance(item, dict) and item.get("url")})
        ),
        source_file=dependency.source_file,
        source_line=dependency.line,
        cvss=cvss,
        source="OSV",
        fixed_version_note=note,
    )


def matching_affected(advisory: dict[str, Any], dependency: Dependency) -> list[dict[str, Any]]:
    """Affected entries for exactly this ecosystem and package name."""
    ecosystem = osv_ecosystem(dependency.ecosystem) or dependency.ecosystem
    expected = canonical_name(dependency.name, dependency.ecosystem)
    matches = []
    for raw in advisory.get("affected", []):
        if not isinstance(raw, dict):
            continue
        package = _dict(raw.get("package"))
        if str(package.get("ecosystem", "")).split(":", 1)[0] != ecosystem:
            continue
        if canonical_name(str(package.get("name", "")), dependency.ecosystem) == expected:
            matches.append(raw)
    return matches


def applicable_fixed_versions(affected: list[dict[str, Any]], dependency: Dependency) -> tuple[tuple[str, ...], str | None]:
    """Fixed versions of the ranges that contain the installed version.

    Never invents a version: every returned value is a ``fixed`` event of the
    advisory. When the installed version cannot be placed in a range, all
    fixed events are returned together with a note.
    """
    version = dependency.version or ""
    ecosystem = osv_ecosystem(dependency.ecosystem) or dependency.ecosystem
    applicable: set[str] = set()
    every: set[str] = set()
    placed = False
    for entry in affected:
        listed = {str(item) for item in entry.get("versions", []) if isinstance(item, (str, int))}
        in_list = version in listed or version.removeprefix("v") in listed
        for raw_range in entry.get("ranges", []):
            if not isinstance(raw_range, dict) or raw_range.get("type") not in {"ECOSYSTEM", "SEMVER"}:
                continue
            for introduced, end, kind in _segments(raw_range.get("events", [])):
                if kind == "fixed":
                    every.add(end)
                contains = _contains(ecosystem, version, introduced, end, kind)
                if contains is None:
                    if in_list and kind == "fixed":
                        applicable.add(end)
                        placed = True
                    continue
                if contains:
                    placed = True
                    if kind == "fixed":
                        applicable.add(end)
        if in_list:
            placed = True
    if applicable:
        return tuple(sort_versions(ecosystem, sorted(applicable))), None
    if placed:
        return (), "The advisory publishes no fixed version for the affected range of this version."
    if every:
        return tuple(sort_versions(ecosystem, sorted(every))), (
            "The installed version could not be placed in an advisory range; the list shows every fixed version in the advisory."
        )
    return (), "The advisory publishes no fixed version."


def _segments(events: Any) -> list[tuple[str | None, str, str]]:
    segments: list[tuple[str | None, str, str]] = []
    introduced: str | None = None
    for event in events if isinstance(events, list) else []:
        if not isinstance(event, dict):
            continue
        if "introduced" in event:
            introduced = str(event["introduced"])
        for kind in ("fixed", "last_affected", "limit"):
            if kind in event:
                segments.append((introduced, str(event[kind]), kind))
                introduced = None
    if introduced is not None:
        segments.append((introduced, "", "open"))
    return segments


def _contains(ecosystem: str, version: str, introduced: str | None, end: str, kind: str) -> bool | None:
    if introduced not in (None, "0"):
        lower = compare(ecosystem, version, introduced)
        if lower is None:
            return None
        if lower < 0:
            return False
    if kind == "open":
        return True
    upper = compare(ecosystem, version, end)
    if upper is None:
        return None
    return upper <= 0 if kind == "last_affected" else upper < 0


def _affected_ranges(affected: list[dict[str, Any]]) -> list[str]:
    result: list[str] = []
    for item in affected:
        for raw_range in item.get("ranges", []):
            if not isinstance(raw_range, dict) or raw_range.get("type") not in {"ECOSYSTEM", "SEMVER"}:
                continue
            for introduced, end, kind in _segments(raw_range.get("events", [])):
                start = "" if introduced in (None, "0") else f">= {introduced}"
                bound = {"fixed": f"< {end}", "limit": f"< {end}", "last_affected": f"<= {end}", "open": ""}[kind]
                rendered = f"{raw_range.get('type')}: " + (", ".join(part for part in (start, bound) if part) or "all versions")
                if rendered not in result:
                    result.append(rendered)
    return result


def _severity(advisory: dict[str, Any], affected: list[dict[str, Any]]) -> tuple[str, float | None]:
    labels: list[str] = []
    scores: list[float] = []
    database = _dict(advisory.get("database_specific"))
    _collect_label(database.get("severity"), labels)
    for raw in advisory.get("severity", []):
        if isinstance(raw, dict) and str(raw.get("type", "")).upper() in {"CVSS_V3", "CVSS_V2"}:
            score = cvss_v3_score(str(raw.get("score", "")))
            if score is not None:
                scores.append(score)
    for item in affected:
        _collect_label(_dict(item.get("ecosystem_specific")).get("severity"), labels)
        _collect_label(_dict(item.get("database_specific")).get("severity"), labels)
    cvss = max(scores) if scores else None
    if cvss is not None:
        labels.append(_cvss_label(cvss))
    rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    known = [label for label in labels if label in rank]
    return (max(known, key=rank.__getitem__) if known else "UNKNOWN"), cvss


def _collect_label(value: Any, labels: list[str]) -> None:
    if isinstance(value, str):
        label = value.strip().upper()
        labels.append("MEDIUM" if label == "MODERATE" else label)


def cvss_v3_score(vector: str) -> float | None:
    """CVSS v3.0/v3.1 base score from a vector string (FIRST specification)."""
    if not vector.startswith(("CVSS:3.0/", "CVSS:3.1/")):
        return None
    metrics = dict(component.split(":", 1) for component in vector.split("/")[1:] if ":" in component)
    try:
        attack_vector = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[metrics["AV"]]
        complexity = {"L": 0.77, "H": 0.44}[metrics["AC"]]
        changed = {"U": False, "C": True}[metrics["S"]]
        privileges = ({"N": 0.85, "L": 0.68, "H": 0.5} if changed else {"N": 0.85, "L": 0.62, "H": 0.27})[metrics["PR"]]
        interaction = {"N": 0.85, "R": 0.62}[metrics["UI"]]
        impact_values = {"H": 0.56, "L": 0.22, "N": 0.0}
        confidentiality, integrity, availability = (impact_values[metrics[key]] for key in ("C", "I", "A"))
    except KeyError:
        return None
    base_impact = 1 - (1 - confidentiality) * (1 - integrity) * (1 - availability)
    impact = 7.52 * (base_impact - 0.029) - 3.25 * (base_impact - 0.02) ** 15 if changed else 6.42 * base_impact
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * attack_vector * complexity * privileges * interaction
    total = min(1.08 * (impact + exploitability), 10) if changed else min(impact + exploitability, 10)
    return _roundup(total)


def _roundup(value: float) -> float:
    """CVSS v3.1 Roundup: smallest one-decimal number >= value, robust to float error."""
    integer = round(value * 100000)
    if integer % 10000 == 0:
        return integer / 100000
    return (math.floor(integer / 10000) + 1) / 10


def _cvss_label(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW" if score > 0 else "UNKNOWN"


def _summary(advisory: dict[str, Any], advisory_id: str) -> str:
    summary = str(advisory.get("summary", "")).strip()
    if summary:
        return summary
    details = str(advisory.get("details", "")).strip()
    if details:
        return details.split("\n\n", 1)[0].replace("\n", " ").strip()[:500]
    return advisory_id


def _deduplicate(items: Iterable[Vulnerability]) -> list[Vulnerability]:
    selected: dict[tuple[str, str, str, str], Vulnerability] = {}
    for item in items:
        key = (item.ecosystem.casefold(), item.package.casefold(), item.installed_version, item.id.casefold())
        current = selected.get(key)
        if current is None:
            selected[key] = item
            continue
        selected[key] = replace(
            current,
            aliases=tuple(sorted(set(current.aliases) | set(item.aliases))),
            references=tuple(sorted(set(current.references) | set(item.references))),
        )
    return sorted(selected.values(), key=lambda item: (item.ecosystem.casefold(), item.package.casefold(), item.installed_version, item.id))


def _ids(result: dict[str, Any]) -> list[str]:
    return [str(item["id"]) for item in result.get("vulns", []) if isinstance(item, dict) and item.get("id")]


def _dependency_order(item: Dependency) -> tuple[int, str, int]:
    return (0 if item.direct else 1, item.source_file.casefold(), item.line or 0)


def _fresh(entry: dict[str, Any], now: float, ttl: int) -> bool:
    stored_at = entry.get("stored_at")
    return isinstance(stored_at, (int, float)) and 0 <= now - float(stored_at) <= ttl


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _chunks(items: list[Any], size: int) -> Iterable[list[Any]]:
    for index in range(0, len(items), size):
        yield items[index : index + size]
