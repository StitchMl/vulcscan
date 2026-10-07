"""Dependency manifest and lockfile parsers.

Parsers read files as data; they never run package managers, build scripts or
project code. A dependency is ``resolved`` when its exact version is known:
from a lockfile (``version_source="lockfile"``) or from an exact pin in a
manifest (``version_source="manifest-pin"``). Only resolved dependencies are
looked up in OSV.
"""

from __future__ import annotations

import json
import re
import tomllib
import xml.etree.ElementTree as ET
from collections.abc import Callable, Iterable
from dataclasses import replace
from pathlib import Path, PurePosixPath
from typing import Any

from .models import Dependency, ScanError

LOCKFILE = "lockfile"
MANIFEST_PIN = "manifest-pin"

_PYTHON_REQUIREMENT = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\s*\[[^\]]*\])?\s*(.*)$")
_EXACT_VERSION = re.compile(r"^v?\d+(?:\.[0-9A-Za-z]+)*(?:[-+.][0-9A-Za-z.+-]*)?$")
_MANIFEST_NAMES = {
    "build.gradle",
    "build.gradle.kts",
    "cargo.lock",
    "cargo.toml",
    "composer.json",
    "composer.lock",
    "directory.packages.props",
    "gemfile",
    "gemfile.lock",
    "go.mod",
    "go.sum",
    "npm-shrinkwrap.json",
    "package-lock.json",
    "package.json",
    "packages.config",
    "packages.lock.json",
    "pipfile",
    "pipfile.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "pom.xml",
    "pyproject.toml",
    "yarn.lock",
}
_LOCKFILES = {
    "cargo.lock",
    "composer.lock",
    "gemfile.lock",
    "npm-shrinkwrap.json",
    "package-lock.json",
    "packages.lock.json",
    "pipfile.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "yarn.lock",
}


def is_manifest_path(relative: str) -> bool:
    path = PurePosixPath(relative.replace("\\", "/"))
    name = path.name.casefold()
    if name.endswith(".csproj"):
        return True
    if name.endswith(".txt") and (name.startswith("requirements") or path.parent.name.casefold() == "requirements"):
        return True
    return name in _MANIFEST_NAMES


_SKIPPED_DIRECTORIES = {".git", ".hg", ".svn", ".venv", "venv", "node_modules", "vendor", "__pycache__", "dist", "build", "target", "bin", "obj"}


def discover_manifests(root: Path) -> list[Path]:
    """Find manifests below ``root`` without following symlinks."""
    found: list[Path] = []
    stack = [root]
    while stack:
        directory = stack.pop()
        try:
            entries = sorted(directory.iterdir(), key=lambda item: item.name.casefold())
        except OSError:
            continue
        for entry in entries:
            if entry.is_symlink():
                continue
            if entry.is_dir():
                if entry.name.casefold() not in _SKIPPED_DIRECTORIES:
                    stack.append(entry)
            elif entry.is_file() and is_manifest_path(entry.relative_to(root).as_posix()):
                found.append(entry)
    return found


def scan_dependencies(root: Path, manifest_paths: Iterable[Path] | None = None) -> tuple[list[Dependency], list[ScanError]]:
    """Parse manifests (discovered below ``root`` when not given).

    Errors are returned per file, never raised.
    """
    root = Path(root).resolve()
    if manifest_paths is None:
        manifest_paths = discover_manifests(root)
    candidates: list[Dependency] = []
    errors: list[ScanError] = []
    for path in sorted(manifest_paths, key=lambda item: _relative(item, root).casefold()):
        relative = _relative(path, root)
        try:
            candidates.extend(_parse_file(path, relative))
        except (OSError, ValueError, UnicodeError, ET.ParseError, tomllib.TOMLDecodeError, json.JSONDecodeError, TypeError, AttributeError) as exc:
            errors.append(ScanError(relative, "dependency-parse", f"{type(exc).__name__}: {exc}"))
    return _prefer_resolved(candidates), errors


def _parse_file(path: Path, source: str) -> list[Dependency]:
    data = path.read_bytes()
    if b"\x00" in data[:4096]:
        raise ValueError("binary manifest skipped")
    text = data.decode("utf-8-sig", errors="replace")
    name = path.name.casefold()
    parser: Callable[[str, str], list[Dependency]]
    if name.endswith(".txt"):
        parser = _parse_requirements
    elif name.endswith(".csproj"):
        parser = _parse_csproj
    else:
        parser = {
            "build.gradle": _parse_gradle,
            "build.gradle.kts": _parse_gradle,
            "cargo.lock": _parse_cargo_lock,
            "cargo.toml": _parse_cargo_toml,
            "composer.json": _parse_composer_json,
            "composer.lock": _parse_composer_lock,
            "directory.packages.props": _parse_central_packages,
            "gemfile": _parse_gemfile,
            "gemfile.lock": _parse_gemfile_lock,
            "go.mod": _parse_go_mod,
            "go.sum": _parse_go_sum,
            "npm-shrinkwrap.json": _parse_package_lock,
            "package-lock.json": _parse_package_lock,
            "package.json": _parse_package_json,
            "packages.config": _parse_packages_config,
            "packages.lock.json": _parse_packages_lock,
            "pipfile": _parse_pipfile,
            "pipfile.lock": _parse_pipfile_lock,
            "pnpm-lock.yaml": _parse_pnpm_lock,
            "poetry.lock": _parse_poetry_lock,
            "pom.xml": _parse_pom,
            "pyproject.toml": _parse_pyproject,
            "yarn.lock": _parse_yarn_lock,
        }[name]
    return parser(text, source)


def _dependency(
    name: str,
    version: str | None,
    ecosystem: str,
    source: str,
    line: int | None,
    *,
    direct: bool,
    version_source: str | None,
    constraint: str | None = None,
) -> Dependency | None:
    clean_name = canonical_name(name, ecosystem)
    if not clean_name:
        return None
    clean_version = _exact_version(version) if version_source else None
    clean_constraint = constraint.strip() if constraint and constraint.strip() else None
    return Dependency(
        name=clean_name,
        version=clean_version,
        ecosystem=ecosystem,
        source_file=source,
        line=line,
        direct=direct,
        resolved=clean_version is not None,
        constraint=clean_constraint,
        version_source=version_source if clean_version is not None else None,
    )


def canonical_name(name: str, ecosystem: str) -> str:
    value = name.strip().strip("\"'")
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", value).casefold()  # PEP 503
    if ecosystem == "Composer":
        return value.casefold()  # Packagist names are lowercase
    return value  # keep the published spelling; npm and RubyGems lookups are case-sensitive


def _exact_version(value: str | None) -> str | None:
    if value is None:
        return None
    clean = str(value).strip().strip("\"'")
    return clean if _EXACT_VERSION.match(clean) else None


# Python ---------------------------------------------------------------------------


def _parse_requirements(text: str, source: str) -> list[Dependency]:
    result: list[Dependency] = []
    for line_number, raw in _logical_lines(text):
        value = re.split(r"\s+#", raw, maxsplit=1)[0].strip()
        if not value or value.startswith(("-", ".", "/", "#")) or "://" in value or " @ " in value:
            continue
        value = value.split(";", 1)[0].strip()
        value = re.sub(r"\s+--hash(?:=|\s).*$", "", value).strip()
        match = _PYTHON_REQUIREMENT.match(value)
        if not match:
            continue
        name, constraint = match.groups()
        exact = re.fullmatch(r"={2,3}\s*([^,\s*]+)", constraint.strip())
        dependency = _dependency(
            name,
            exact.group(1) if exact else None,
            "PyPI",
            source,
            line_number,
            direct=True,
            version_source=MANIFEST_PIN if exact else None,
            constraint=constraint,
        )
        if dependency:
            result.append(dependency)
    return result


def _logical_lines(text: str) -> list[tuple[int, str]]:
    result: list[tuple[int, str]] = []
    current = ""
    start = 1
    for number, line in enumerate(text.splitlines(), 1):
        if not current:
            start = number
        stripped = line.rstrip()
        current += stripped.removesuffix("\\").strip() + " "
        if not stripped.endswith("\\"):
            result.append((start, current.strip()))
            current = ""
    if current:
        result.append((start, current.strip()))
    return result


def _parse_pyproject(text: str, source: str) -> list[Dependency]:
    document = tomllib.loads(text)
    result: list[Dependency] = []
    project = _mapping(document.get("project"))
    requirements = list(_string_list(project.get("dependencies")))
    for values in _mapping(project.get("optional-dependencies")).values():
        requirements.extend(_string_list(values))
    for values in _mapping(document.get("dependency-groups")).values():
        requirements.extend(_string_list(values))
    for requirement in requirements:
        value = requirement.split(";", 1)[0].strip()
        match = _PYTHON_REQUIREMENT.match(value)
        if not match or " @ " in value or "://" in value:
            continue
        name, constraint = match.groups()
        exact = re.fullmatch(r"={2,3}\s*([^,\s*]+)", constraint.strip())
        dependency = _dependency(
            name,
            exact.group(1) if exact else None,
            "PyPI",
            source,
            _line_of(text, requirement),
            direct=True,
            version_source=MANIFEST_PIN if exact else None,
            constraint=constraint,
        )
        if dependency:
            result.append(dependency)
    poetry = _mapping(_mapping(document.get("tool")).get("poetry"))
    sections = [_mapping(poetry.get("dependencies")), _mapping(poetry.get("dev-dependencies"))]
    sections.extend(_mapping(_mapping(group).get("dependencies")) for group in _mapping(poetry.get("group")).values())
    for section in sections:
        for name, raw_constraint in section.items():
            if name.casefold() == "python":
                continue
            constraint = _toml_constraint(raw_constraint)
            exact = _poetry_exact(constraint)
            dependency = _dependency(
                name,
                exact,
                "PyPI",
                source,
                _line_of_key(text, name),
                direct=True,
                version_source=MANIFEST_PIN if exact else None,
                constraint=constraint,
            )
            if dependency:
                result.append(dependency)
    return result


def _poetry_exact(constraint: str | None) -> str | None:
    """Poetry treats a bare version and ``==x`` as exact requirements."""
    if not constraint:
        return None
    match = re.fullmatch(r"\s*(?:==)?\s*(\d[0-9A-Za-z.+!-]*)\s*", constraint)
    return match.group(1) if match and "*" not in constraint else None


def _parse_poetry_lock(text: str, source: str) -> list[Dependency]:
    document = tomllib.loads(text)
    result: list[Dependency] = []
    for raw in document.get("package", []):
        item = _mapping(raw)
        origin = str(_mapping(item.get("source")).get("type", "")).casefold()
        registry = origin in {"", "legacy", "pypi"}
        name = str(item.get("name", ""))
        dependency = _dependency(
            name,
            _optional_string(item.get("version")),
            "PyPI",
            source,
            _line_of_toml_package(text, name),
            direct=False,
            version_source=LOCKFILE if registry else None,
            constraint=None if registry else f"{origin} source",
        )
        if dependency:
            result.append(dependency)
    return result


def _parse_pipfile(text: str, source: str) -> list[Dependency]:
    document = tomllib.loads(text)
    result: list[Dependency] = []
    for section in ("packages", "dev-packages"):
        for name, raw_constraint in _mapping(document.get(section)).items():
            constraint = _toml_constraint(raw_constraint)
            exact = re.fullmatch(r"\s*==\s*(\d[^,\s*]*)\s*", constraint or "")
            dependency = _dependency(
                name,
                exact.group(1) if exact else None,
                "PyPI",
                source,
                _line_of_key(text, name),
                direct=True,
                version_source=MANIFEST_PIN if exact else None,
                constraint=constraint,
            )
            if dependency:
                result.append(dependency)
    return result


def _parse_pipfile_lock(text: str, source: str) -> list[Dependency]:
    document = json.loads(text)
    result: list[Dependency] = []
    for section in ("default", "develop"):
        for name, raw in _mapping(document.get(section)).items():
            item = _mapping(raw)
            version = _optional_string(item.get("version"))
            exact = re.fullmatch(r"\s*==\s*(\S+)\s*", version or "")
            dependency = _dependency(
                name,
                exact.group(1) if exact else None,
                "PyPI",
                source,
                _line_of_json_key(text, name),
                direct=False,
                version_source=LOCKFILE if exact else None,
            )
            if dependency:
                result.append(dependency)
    return result


# JavaScript -----------------------------------------------------------------------


def _parse_package_json(text: str, source: str) -> list[Dependency]:
    document = json.loads(text)
    result: list[Dependency] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        for name, raw_constraint in _mapping(document.get(section)).items():
            constraint = str(raw_constraint)
            exact = re.fullmatch(r"=?v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)", constraint.strip())
            dependency = _dependency(
                name,
                exact.group(1) if exact else None,
                "npm",
                source,
                _line_of_json_key(text, name),
                direct=True,
                version_source=MANIFEST_PIN if exact else None,
                constraint=constraint,
            )
            if dependency:
                result.append(dependency)
    return result


def _parse_package_lock(text: str, source: str) -> list[Dependency]:
    document = json.loads(text)
    result: list[Dependency] = []
    packages = _mapping(document.get("packages"))
    if packages:
        for package_path, raw in packages.items():
            if not package_path or "node_modules/" not in package_path.replace("\\", "/"):
                continue  # the root project or a workspace folder
            item = _mapping(raw)
            if item.get("link"):
                continue
            name = _optional_string(item.get("name")) or _npm_name_from_path(package_path)
            resolved_url = str(item.get("resolved", ""))
            registry = not resolved_url or resolved_url.startswith(("https://", "http://"))
            dependency = _dependency(
                name,
                _optional_string(item.get("version")),
                "npm",
                source,
                _line_near_json_object(text, package_path, "version"),
                direct=_is_top_level_node_module(package_path),
                version_source=LOCKFILE if registry else None,
                constraint=None if registry else resolved_url,
            )
            if dependency:
                result.append(dependency)
    else:
        _walk_npm_v1(_mapping(document.get("dependencies")), text, source, result)
    return result


def _walk_npm_v1(dependencies: dict[str, Any], text: str, source: str, result: list[Dependency]) -> None:
    for name, raw in dependencies.items():
        item = _mapping(raw)
        version = _optional_string(item.get("version"))
        dependency = _dependency(
            name,
            version,
            "npm",
            source,
            _line_of_json_key(text, name),
            direct=False,
            version_source=LOCKFILE,
        )
        if dependency:
            result.append(dependency)
        _walk_npm_v1(_mapping(item.get("dependencies")), text, source, result)


def _parse_yarn_lock(text: str, source: str) -> list[Dependency]:
    result: list[Dependency] = []
    header: str | None = None
    header_line = 0
    for line_number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not line[:1].isspace() and stripped.endswith(":"):
            header = stripped[:-1]
            header_line = line_number
            continue
        version_line = re.match(r"^\s+version:?\s+\"?([^\"\s]+)\"?\s*$", line)
        if header and version_line:
            for descriptor in _split_yarn_descriptors(header):
                if re.search(r"@(?:workspace|link|portal|file|exec|git\+|github):", descriptor):
                    continue
                dependency = _dependency(
                    _yarn_descriptor_name(descriptor),
                    version_line.group(1),
                    "npm",
                    source,
                    header_line,
                    direct=False,
                    version_source=LOCKFILE,
                )
                if dependency:
                    result.append(dependency)
            header = None
    return result


def _parse_pnpm_lock(text: str, source: str) -> list[Dependency]:
    result: list[Dependency] = []
    lines = text.splitlines()
    section: str | None = None
    for number, line in enumerate(lines, 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()
        if indent == 0 and stripped.endswith(":"):
            section = stripped[:-1].strip("'\"")
            continue
        if section in {"packages", "snapshots"} and indent == 2 and stripped.endswith(":"):
            parsed = _pnpm_package_key(stripped[:-1].strip("'\""))
            if parsed:
                dependency = _dependency(parsed[0], parsed[1], "npm", source, number, direct=False, version_source=LOCKFILE)
                if dependency:
                    result.append(dependency)
    result.extend(_parse_pnpm_importers(lines, source))
    return result


def _parse_pnpm_importers(lines: list[str], source: str) -> list[Dependency]:
    result: list[Dependency] = []
    in_importers = False
    dependency_indent: int | None = None
    current_name: str | None = None
    current_line = 0
    for number, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped:
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent == 0:
            in_importers = stripped == "importers:"
            dependency_indent = None
            current_name = None
            continue
        if not in_importers:
            continue
        if stripped in {"dependencies:", "devDependencies:", "optionalDependencies:"}:
            dependency_indent = indent
            current_name = None
            continue
        if dependency_indent is None or indent <= dependency_indent:
            dependency_indent = None
            current_name = None
            continue
        if indent == dependency_indent + 2 and stripped.endswith(":"):
            current_name = stripped[:-1].strip("'\"")
            current_line = number
        elif current_name and indent == dependency_indent + 4 and stripped.startswith("version:"):
            version = stripped.split(":", 1)[1].strip(" '\"").split("(", 1)[0]
            dependency = _dependency(current_name, version, "npm", source, current_line, direct=True, version_source=LOCKFILE)
            if dependency:
                result.append(dependency)
            current_name = None
    return result


# PHP ------------------------------------------------------------------------------


def _parse_composer_json(text: str, source: str) -> list[Dependency]:
    document = json.loads(text)
    result: list[Dependency] = []
    for section in ("require", "require-dev"):
        for name, raw_constraint in _mapping(document.get(section)).items():
            if name == "php" or name.startswith(("ext-", "lib-")) or "/" not in name:
                continue
            constraint = str(raw_constraint)
            exact = re.fullmatch(r"=?v?(\d+(?:\.\d+){1,3}(?:-[0-9A-Za-z.]+)?)", constraint.strip())
            dependency = _dependency(
                name,
                exact.group(1) if exact else None,
                "Composer",
                source,
                _line_of_json_key(text, name),
                direct=True,
                version_source=MANIFEST_PIN if exact else None,
                constraint=constraint,
            )
            if dependency:
                result.append(dependency)
    return result


def _parse_composer_lock(text: str, source: str) -> list[Dependency]:
    document = json.loads(text)
    result: list[Dependency] = []
    for section in ("packages", "packages-dev"):
        for raw in document.get(section, []):
            item = _mapping(raw)
            name = str(item.get("name", ""))
            local = str(_mapping(item.get("dist")).get("type", "")).casefold() == "path"
            version = _optional_string(item.get("version"))
            dependency = _dependency(
                name,
                version.removeprefix("v") if version and re.match(r"v\d", version) else version,
                "Composer",
                source,
                _line_of_json_value(text, "name", name),
                direct=False,
                version_source=None if local else LOCKFILE,
            )
            if dependency:
                result.append(dependency)
    return result


# Java -----------------------------------------------------------------------------


def _parse_pom(text: str, source: str) -> list[Dependency]:
    _reject_unsafe_xml(text)
    root = ET.fromstring(text)
    properties: dict[str, str] = {}
    for element in root.iter():
        if _local_name(element.tag) == "properties":
            for child in element:
                if child.text:
                    properties[_local_name(child.tag)] = child.text.strip()
    result: list[Dependency] = []
    for element in root.iter():
        if _local_name(element.tag) != "dependency":
            continue
        values = {_local_name(child.tag): (child.text or "").strip() for child in element}
        group, artifact = values.get("groupId", ""), values.get("artifactId", "")
        if not group or not artifact:
            continue
        constraint = values.get("version") or None
        if constraint and re.fullmatch(r"\$\{[\w.-]+\}", constraint):
            constraint = properties.get(constraint[2:-1], constraint)
        exact = constraint if constraint and not re.search(r"[\[\](),$]", constraint) else None
        dependency = _dependency(
            f"{group}:{artifact}",
            exact,
            "Maven",
            source,
            _line_of(text, f"<artifactId>{artifact}</artifactId>"),
            direct=True,
            version_source=MANIFEST_PIN if exact else None,
            constraint=constraint,
        )
        if dependency:
            result.append(dependency)
    return result


_GRADLE_CONFIGURATIONS = r"(?:api|implementation|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly|testCompileOnly|annotationProcessor|kapt|ksp|classpath|compile|testCompile|runtime)"


def _parse_gradle(text: str, source: str) -> list[Dependency]:
    result: list[Dependency] = []
    patterns = (
        re.compile(rf"(?m)^\s*{_GRADLE_CONFIGURATIONS}\s*(?:\(\s*)?[\"']([^:\"'\s]+):([^:\"'\s]+):([^:\"'@\s]+)(?:@\w+)?[\"']"),
        re.compile(
            rf"(?m)^\s*{_GRADLE_CONFIGURATIONS}\s*(?:\(\s*)?group\s*[:=]\s*[\"']([^\"']+)[\"']\s*,\s*name\s*[:=]\s*[\"']([^\"']+)[\"']\s*,\s*version\s*[:=]\s*[\"']([^\"']+)[\"']"
        ),
    )
    for pattern in patterns:
        for match in pattern.finditer(text):
            group, artifact, constraint = match.groups()
            exact = constraint if not re.search(r"[\[\](),$+]", constraint) else None
            dependency = _dependency(
                f"{group}:{artifact}",
                exact,
                "Maven",
                source,
                text.count("\n", 0, match.start()) + 1,
                direct=True,
                version_source=MANIFEST_PIN if exact else None,
                constraint=constraint,
            )
            if dependency:
                result.append(dependency)
    return result


# Go -------------------------------------------------------------------------------


def _parse_go_mod(text: str, source: str) -> list[Dependency]:
    result: list[Dependency] = []
    replacements: dict[str, str | None] = {}
    block: str | None = None
    entries: list[tuple[str, str, int, bool]] = []
    for number, raw_line in enumerate(text.splitlines(), 1):
        indirect = "// indirect" in raw_line
        line = raw_line.split("//", 1)[0].strip()
        if not line:
            continue
        opening = re.fullmatch(r"(require|replace|exclude|retract)\s*\(", line)
        if opening:
            block = opening.group(1)
            continue
        if block and line == ")":
            block = None
            continue
        keyword, _, rest = line.partition(" ")
        if block is None and keyword in {"require", "replace"}:
            kind, body = keyword, rest.strip()
        elif block in {"require", "replace"}:
            kind, body = block, line
        else:
            continue
        if kind == "require":
            fields = body.split()
            if len(fields) >= 2:
                entries.append((fields[0], fields[1], number, not indirect))
        else:
            left, _, right = body.partition("=>")
            target = right.split()
            module = left.split()[0] if left.split() else ""
            if module:
                # "=> other/module v1.2.3" pins a version; "=> ../local" has none.
                replacements[module] = target[1] if len(target) == 2 and target[1].startswith("v") else None
    for module, version, number, direct in entries:
        replaced = module in replacements
        dependency = _dependency(
            module,
            replacements[module] if replaced else version,
            "Go",
            source,
            number,
            direct=direct,
            version_source=LOCKFILE if not replaced or replacements[module] else None,
            constraint="replaced by a local module" if replaced and not replacements[module] else None,
        )
        if dependency:
            result.append(dependency)
    return result


def _parse_go_sum(text: str, source: str) -> list[Dependency]:
    result: list[Dependency] = []
    for number, line in enumerate(text.splitlines(), 1):
        fields = line.split()
        if len(fields) < 2:
            continue
        dependency = _dependency(
            fields[0],
            None,
            "Go",
            source,
            number,
            direct=False,
            version_source=None,
            constraint=f"{fields[1].removesuffix('/go.mod')} (go.sum checksum; not proof of use)",
        )
        if dependency:
            result.append(dependency)
    return result


# Ruby -----------------------------------------------------------------------------


def _parse_gemfile(text: str, source: str) -> list[Dependency]:
    result: list[Dependency] = []
    pattern = re.compile(r"(?m)^\s*gem\s*\(?\s*[\"']([^\"']+)[\"'](?:\s*,\s*[\"']([^\"']+)[\"'])?")
    for match in pattern.finditer(text):
        name, constraint = match.groups()
        exact = re.fullmatch(r"(?:=\s*)?(\d[0-9A-Za-z.]*)", (constraint or "").strip())
        dependency = _dependency(
            name,
            exact.group(1) if exact else None,
            "RubyGems",
            source,
            text.count("\n", 0, match.start()) + 1,
            direct=True,
            version_source=MANIFEST_PIN if exact else None,
            constraint=constraint,
        )
        if dependency:
            result.append(dependency)
    return result


def _parse_gemfile_lock(text: str, source: str) -> list[Dependency]:
    result: list[Dependency] = []
    direct_names: set[str] = set()
    section: str | None = None
    in_specs = False
    specs: list[tuple[str, str, int, str]] = []
    for number, line in enumerate(text.splitlines(), 1):
        if line and not line[0].isspace():
            section = line.strip()
            in_specs = False
            continue
        if line.strip() == "specs:":
            in_specs = section in {"GEM", "GIT", "PATH"}
            continue
        if in_specs and re.match(r"^    \S", line):
            match = re.match(r"^    ([^\s(]+) \(([^)]+)\)", line)
            if match:
                specs.append((match.group(1), match.group(2), number, section or ""))
        elif section == "DEPENDENCIES":
            match = re.match(r"^  ([^\s(!]+)", line)
            if match:
                direct_names.add(match.group(1))
    for name, raw_version, number, origin in specs:
        version = re.sub(r"-(?:x86|x64|arm|aarch64|java|mingw|mswin|universal|darwin|linux|ruby)\b.*$", "", raw_version)
        dependency = _dependency(
            name,
            version,
            "RubyGems",
            source,
            number,
            direct=name in direct_names,
            version_source=LOCKFILE if origin == "GEM" else None,
            constraint=None if origin == "GEM" else f"{origin.lower()} source",
        )
        if dependency:
            result.append(dependency)
    return result


# .NET -----------------------------------------------------------------------------


def _parse_packages_config(text: str, source: str) -> list[Dependency]:
    _reject_unsafe_xml(text)
    result: list[Dependency] = []
    for element in ET.fromstring(text).iter():
        if _local_name(element.tag) != "package":
            continue
        name = element.attrib.get("id", "")
        dependency = _dependency(
            name,
            element.attrib.get("version"),
            "NuGet",
            source,
            _line_of(text, f'"{name}"'),
            direct=True,
            version_source=MANIFEST_PIN,
        )
        if dependency:
            result.append(dependency)
    return result


def _parse_csproj(text: str, source: str) -> list[Dependency]:
    return _package_items(text, source, "PackageReference")


def _parse_central_packages(text: str, source: str) -> list[Dependency]:
    return _package_items(text, source, "PackageVersion")


def _package_items(text: str, source: str, tag: str) -> list[Dependency]:
    _reject_unsafe_xml(text)
    result: list[Dependency] = []
    for element in ET.fromstring(text).iter():
        if _local_name(element.tag) != tag:
            continue
        name = element.attrib.get("Include") or element.attrib.get("Update") or ""
        constraint = element.attrib.get("Version")
        if constraint is None:
            for child in element:
                if _local_name(child.tag) == "Version":
                    constraint = (child.text or "").strip()
                    break
        exact = re.fullmatch(r"\[?\s*(\d[0-9A-Za-z.+-]*)\s*\]?", constraint or "")
        if exact and constraint and constraint.startswith("[") != constraint.endswith("]"):
            exact = None
        dependency = _dependency(
            name,
            exact.group(1) if exact else None,
            "NuGet",
            source,
            _line_of(text, f'"{name}"'),
            direct=True,
            version_source=MANIFEST_PIN if exact else None,
            constraint=constraint,
        )
        if dependency:
            result.append(dependency)
    return result


def _parse_packages_lock(text: str, source: str) -> list[Dependency]:
    document = json.loads(text)
    result: list[Dependency] = []
    for framework in _mapping(document.get("dependencies")).values():
        for name, raw in _mapping(framework).items():
            item = _mapping(raw)
            kind = str(item.get("type", "")).casefold()
            if kind == "project":
                continue
            dependency = _dependency(
                name,
                _optional_string(item.get("resolved")),
                "NuGet",
                source,
                _line_of_json_key(text, name),
                direct=kind == "direct",
                version_source=LOCKFILE,
                constraint=_optional_string(item.get("requested")),
            )
            if dependency:
                result.append(dependency)
    return result


# Rust -----------------------------------------------------------------------------


def _parse_cargo_toml(text: str, source: str) -> list[Dependency]:
    document = tomllib.loads(text)
    result: list[Dependency] = []

    def visit(value: Any) -> None:
        if not isinstance(value, dict):
            return
        for key, raw in value.items():
            if key in {"dependencies", "dev-dependencies", "build-dependencies"} and isinstance(raw, dict):
                for name, specification in raw.items():
                    constraint = _toml_constraint(specification)
                    package = str(_mapping(specification).get("package", name))
                    exact = re.fullmatch(r"\s*=\s*(\d[^,\s]*)\s*", constraint or "")
                    dependency = _dependency(
                        package,
                        exact.group(1) if exact else None,
                        "Cargo",
                        source,
                        _line_of_key(text, name),
                        direct=True,
                        version_source=MANIFEST_PIN if exact else None,
                        constraint=constraint,
                    )
                    if dependency:
                        result.append(dependency)
            elif isinstance(raw, dict):
                visit(raw)

    visit(document)
    return result


def _parse_cargo_lock(text: str, source: str) -> list[Dependency]:
    document = tomllib.loads(text)
    result: list[Dependency] = []
    for raw in document.get("package", []):
        item = _mapping(raw)
        name = str(item.get("name", ""))
        origin = str(item.get("source", ""))
        registry = origin.startswith(("registry+", "sparse+"))
        dependency = _dependency(
            name,
            _optional_string(item.get("version")),
            "Cargo",
            source,
            _line_of_toml_package(text, name),
            direct=False,
            version_source=LOCKFILE if registry else None,
            constraint=None if registry else ("workspace crate" if not origin else origin.split("+", 1)[0] + " source"),
        )
        if dependency:
            result.append(dependency)
    return result


# Selection ------------------------------------------------------------------------


def _prefer_resolved(candidates: Iterable[Dependency]) -> list[Dependency]:
    """Keep lockfile versions over manifest declarations of the same project.

    A lockfile covers manifests in its own directory and below (workspaces).
    A covered manifest entry is dropped; its constraint and "direct" flag move
    to the matching lockfile entry. Uncovered manifest entries stay.
    """
    items = list(candidates)
    locks: dict[tuple[str, str], list[int]] = {}
    for index, item in enumerate(items):
        if item.version_source == LOCKFILE:
            locks.setdefault((item.ecosystem, item.name.casefold()), []).append(index)
    keep = [True] * len(items)
    for index, item in enumerate(items):
        if item.version_source == LOCKFILE or _is_lockfile(item.source_file):
            continue
        covering = [lock for lock in locks.get((item.ecosystem, item.name.casefold()), []) if _covers(items[lock].source_file, item.source_file)]
        if not covering:
            continue
        keep[index] = False
        top_level = [lock for lock in covering if items[lock].direct] or (covering if len(covering) == 1 else [])
        for lock in top_level:
            items[lock] = replace(items[lock], direct=True, constraint=items[lock].constraint or item.constraint)
    result: dict[tuple[str, str, str | None], Dependency] = {}
    for index, item in enumerate(items):
        if not keep[index]:
            continue
        key = (item.ecosystem, item.name.casefold(), item.version)
        current = result.get(key)
        if current is None or _preference(item) < _preference(current):
            result[key] = item
    return sorted(
        result.values(),
        key=lambda item: (item.ecosystem.casefold(), item.name.casefold(), item.version or "", item.source_file.casefold(), item.line or 0),
    )


def _is_lockfile(source_file: str) -> bool:
    return PurePosixPath(source_file).name.casefold() in _LOCKFILES


def _covers(lockfile: str, manifest: str) -> bool:
    lock_directory = PurePosixPath(lockfile).parent
    manifest_directory = PurePosixPath(manifest).parent
    return lock_directory == manifest_directory or lock_directory in manifest_directory.parents or str(lock_directory) == "."


def _preference(item: Dependency) -> tuple[int, int, int, str, int]:
    return (
        0 if item.version_source == LOCKFILE else 1 if item.resolved else 2,
        0 if item.direct else 1,
        0 if item.line is not None else 1,
        item.source_file.casefold(),
        item.line or 0,
    )


# Helpers --------------------------------------------------------------------------


def _toml_constraint(value: Any) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        raw = value.get("version")
        return str(raw) if raw is not None else None
    return None


def _npm_name_from_path(path: str) -> str:
    tail = path.replace("\\", "/").rsplit("node_modules/", 1)[-1]
    parts = tail.split("/")
    return "/".join(parts[:2]) if tail.startswith("@") else parts[0]


def _is_top_level_node_module(path: str) -> bool:
    normalized = path.replace("\\", "/").strip("/")
    if not normalized.startswith("node_modules/"):
        return False
    tail = normalized[len("node_modules/") :]
    return len(tail.split("/")) == (2 if tail.startswith("@") else 1)


def _split_yarn_descriptors(header: str) -> list[str]:
    return [part.strip().strip("\"'") for part in re.split(r",\s*(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)", header) if part.strip()]


def _yarn_descriptor_name(descriptor: str) -> str:
    match = re.match(r"^(@[^/]+/[^@]+|[^@]+)@", descriptor)
    return match.group(1) if match else ""


def _pnpm_package_key(key: str) -> tuple[str, str] | None:
    clean = key.strip("/").split("(", 1)[0]
    if not clean:
        return None
    if clean.startswith("@"):
        if clean.count("/") >= 2:
            parts = clean.split("/")
            name, version = f"{parts[0]}/{parts[1]}", parts[2]
        else:
            match = re.match(r"^(@[^/]+/[^@]+)@(.+)$", clean)
            if not match:
                return None
            name, version = match.groups()
    elif "/" in clean:
        name, version = clean.rsplit("/", 1)
    else:
        match = re.match(r"^(.+?)@([^@]+)$", clean)
        if not match:
            return None
        name, version = match.groups()
    return name, version.split("_", 1)[0]  # pnpm v5 appends "_peer@x" suffixes


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _string_list(value: Any) -> list[str]:
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def _optional_string(value: Any) -> str | None:
    return str(value) if value is not None else None


def _relative(path: Path, root: Path) -> str:
    try:
        return Path(path).resolve().relative_to(root).as_posix()
    except ValueError:
        return Path(path).as_posix()


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _line_of(text: str, needle: str) -> int | None:
    if not needle:
        return None
    offset = text.find(needle)
    if offset < 0:
        offset = text.casefold().find(needle.casefold())
    return _line_number(text, offset) if offset >= 0 else None


def _line_of_key(text: str, key: str) -> int | None:
    match = re.search(rf"(?m)^\s*[\"']?{re.escape(key)}[\"']?\s*=", text)
    return _line_number(text, match.start()) if match else _line_of(text, key)


def _line_of_toml_package(text: str, name: str) -> int | None:
    match = re.search(rf"(?m)^name\s*=\s*\"{re.escape(name)}\"\s*$", text)
    return _line_number(text, match.start()) if match else None


def _line_of_json_key(text: str, key: str) -> int | None:
    match = re.search(rf'(?m)^\s*"{re.escape(key)}"\s*:', text)
    return _line_number(text, match.start()) if match else _line_of(text, f'"{key}"')


def _line_of_json_value(text: str, key: str, value: str) -> int | None:
    match = re.search(rf'"{re.escape(key)}"\s*:\s*"{re.escape(value)}"', text)
    return _line_number(text, match.start()) if match else None


def _line_near_json_object(text: str, object_key: str, field: str) -> int | None:
    object_match = re.search(rf'(?m)^\s*"{re.escape(object_key)}"\s*:', text)
    if not object_match:
        return None
    field_match = re.search(rf'(?m)^\s*"{re.escape(field)}"\s*:', text[object_match.end() :])
    offset = object_match.end() + field_match.start() if field_match else object_match.start()
    return _line_number(text, offset)


def _reject_unsafe_xml(text: str) -> None:
    folded = text.casefold()
    if "<!doctype" in folded or "<!entity" in folded:
        raise ValueError("XML with DTD or entity declarations is not parsed")


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]
