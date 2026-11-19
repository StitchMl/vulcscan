"""Repository discovery and scan orchestration."""

from __future__ import annotations

import fnmatch
import os
import platform
import stat
import time
from concurrent.futures import ThreadPoolExecutor
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from .attack_surface import map_attack_surface
from .binary import analyze_binary, binary_kind, looks_like_binary
from .dependencies import is_manifest_path, scan_dependencies
from .guidance import enrich_finding
from .javascript import analyze_javascript
from .js_interproc import imported_sink_map
from .js_timing import analyze_javascript_timing
from .java_zip_slip import analyze_java_zip_slip
from .go_zip_slip import analyze_go_zip_slip
from .lexical import lexical_findings
from .remote import has_remote_source
from .models import SEVERITY_RANK, ScanConfig, ScanError, ScanResult
from .python_analysis import PythonProject
from .python_argument_injection import analyze_argument_injection
from .python_tar_extraction import analyze_tar_extraction
from .python_timing import analyze_timing_comparisons
from .python_route_authz import analyze_route_authz
from .source import decode_source
from .structured import CATALOGS, analyze_structured
from .suppressions import is_suppressed, suppression_index

DEFAULT_EXCLUDED_DIRECTORIES = frozenset(
    {
        ".git",
        ".svn",
        ".hg",
        ".idea",
        ".vscode",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".nox",
        "node_modules",
        "bower_components",
        "venv",
        ".venv",
        "__pycache__",
        "site-packages",
        "vendor",
        "coverage",
        ".coverage",
        ".next",
        ".nuxt",
        ".terraform",
    }
)
MAX_MANIFEST_SIZE = 32 * 1024 * 1024
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)

LANGUAGE_EXTENSIONS = {
    ".py": "Python",
    ".pyw": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".mts": "TypeScript",
    ".cts": "TypeScript",
    ".php": "PHP",
    ".phtml": "PHP",
    ".java": "Java",
    ".cs": "C#",
    ".go": "Go",
    ".rb": "Ruby",
    ".c": "C",
    ".h": "C",
    ".cc": "C++",
    ".cpp": "C++",
    ".cxx": "C++",
    ".hpp": "C++",
    ".hh": "C++",
    ".sh": "Shell",
    ".bash": "Shell",
    ".zsh": "Shell",
    ".ps1": "PowerShell",
    ".psm1": "PowerShell",
    ".bat": "Batch",
    ".cmd": "Batch",
    ".rs": "Rust",
    ".swift": "Swift",
    ".kt": "Kotlin",
    ".kts": "Kotlin",
    ".scala": "Scala",
    ".sql": "SQL",
    ".html": "HTML",
    ".htm": "HTML",
    ".css": "CSS",
    ".svg": "SVG",
    ".xml": "XML",
    ".config": "XML",
    ".csproj": "XML",
    ".yml": "YAML",
    ".yaml": "YAML",
    ".json": "JSON",
    ".toml": "TOML",
    ".ini": "Configuration",
    ".cfg": "Configuration",
    ".conf": "Configuration",
    ".properties": "Configuration",
    ".env": "Environment",
    ".tf": "Terraform",
    ".hcl": "HCL",
    ".pem": "Key",
    ".key": "Key",
}
_SPECIAL_NAMES = {
    "dockerfile": "Dockerfile",
    "containerfile": "Dockerfile",
    "gemfile": "Ruby",
    "rakefile": "Ruby",
    "jenkinsfile": "Configuration",
    "procfile": "Configuration",
    "makefile": "Configuration",
    "pipfile": "TOML",
    "go.mod": "Manifest",
    "go.sum": "Manifest",
    "gemfile.lock": "Manifest",
    "cargo.lock": "Manifest",
    "poetry.lock": "Manifest",
    "yarn.lock": "Manifest",
}
_SKIPPED_SUFFIXES = (".min.js", ".min.css", ".map", ".bundle.js")
_CODE_ANALYSIS_SKIP = {"Manifest"}
_TEST_DIRECTORIES = frozenset({"test", "tests", "__tests__", "spec", "specs", "fixtures", "__fixtures__"})
_TEST_FILENAMES = frozenset({"conftest.py", "pytest.ini"})


def _is_test_filename(relative: str) -> bool:
    name = relative.rsplit("/", 1)[-1].casefold()
    return (
        name in _TEST_FILENAMES
        or (name.startswith("test_") and name.endswith(".py"))
        or name.endswith("_test.go")
        or any(name.endswith(extension) for extension in (
            ".test.js", ".test.jsx", ".test.ts", ".test.tsx",
            ".spec.js", ".spec.jsx", ".spec.ts", ".spec.tsx",
        ))
    )




@dataclass(frozen=True, slots=True)
class SourceFile:
    path: Path
    relative: str
    language: str
    text: str


@dataclass(frozen=True, slots=True)
class BinaryFile:
    relative: str
    data: bytes

    @property
    def language(self) -> str:
        return binary_kind(self.data)


class RepositoryDiscovery:
    """Walk the repository once; never follow symlinks or Windows reparse points."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self.root = config.root.resolve()
        self.errors: list[ScanError] = []
        self.discovered = 0
        self.analyzed = 0
        self.manifests: list[Path] = []
        self.binaries: list[BinaryFile] = []

    def run(self) -> list[SourceFile]:
        files: list[SourceFile] = []
        stack = [self.root]
        visited: set[tuple[int, int]] = set()
        while stack:
            directory = stack.pop()
            try:
                directory_stat = directory.stat(follow_symlinks=False)
                identity = (directory_stat.st_dev, directory_stat.st_ino)
                if identity in visited and identity != (0, 0):
                    continue
                visited.add(identity)
                with os.scandir(directory) as iterator:
                    entries = sorted(iterator, key=lambda item: item.name.casefold())
            except OSError as exc:
                self.errors.append(self._error(directory, "discovery", exc))
                continue
            children: list[Path] = []
            for entry in entries:
                path = Path(entry.path)
                relative = self._relative(path)
                try:
                    metadata = entry.stat(follow_symlinks=False)
                    is_link = entry.is_symlink() or bool(getattr(metadata, "st_file_attributes", 0) & _REPARSE_POINT)
                    if entry.is_dir(follow_symlinks=False):
                        if not is_link and not self._excluded_directory(entry.name, relative):
                            children.append(path)
                        continue
                    if is_link or not entry.is_file(follow_symlinks=False):
                        continue
                    if self._excluded_file(relative):
                        continue
                    self.discovered += 1
                    if is_manifest_path(relative):
                        if metadata.st_size <= MAX_MANIFEST_SIZE:
                            self.manifests.append(path)
                        else:
                            self.errors.append(ScanError(relative, "dependency-parse", f"manifest exceeds {MAX_MANIFEST_SIZE} bytes"))
                    source = self._read(path, relative, metadata.st_size)
                    if source is not None:
                        files.append(source)
                except OSError as exc:
                    self.errors.append(self._error(path, "read", exc))
            stack.extend(reversed(children))
        files.sort(key=lambda item: item.relative.casefold())
        self.manifests.sort(key=lambda item: self._relative(item).casefold())
        self.analyzed = len(files) + len(self.binaries)
        return files

    def _read(self, path: Path, relative: str, size: int) -> SourceFile | None:
        name = path.name.casefold()
        if name.endswith(_SKIPPED_SUFFIXES):
            return None
        if size > self.config.max_file_size:
            return None
        language = classify_name(path.name)
        with path.open("rb") as handle:
            head = handle.read(256)
        if looks_like_binary(path, head):
            self.binaries.append(BinaryFile(relative, path.read_bytes()))
            return None
        if language is None and path.suffix:
            return None  # unknown non-binary extension: not read in full
        if language is None:
            language = classify_shebang(head)
            if language is None:
                return None
        data = path.read_bytes()
        if _is_binary(data):
            return None
        return SourceFile(path, relative, language, decode_source(data))

    def _excluded_directory(self, name: str, relative: str) -> bool:
        if name.casefold() in DEFAULT_EXCLUDED_DIRECTORIES:
            return True
        if self.config.exclude_tests and name.casefold() in _TEST_DIRECTORIES:
            return True
        return self._matches_user_exclude(relative, directory=True)

    def _excluded_file(self, relative: str) -> bool:
        if self.config.exclude_tests and _is_test_filename(relative):
            return True
        if self.config.only_files is not None and relative not in self.config.only_files:
            return True
        return self._matches_user_exclude(relative, directory=False)

    def _matches_user_exclude(self, relative: str, *, directory: bool) -> bool:
        candidate = relative.replace("\\", "/").casefold()
        name = candidate.rsplit("/", 1)[-1]
        for raw_pattern in self.config.excludes:
            pattern = raw_pattern.replace("\\", "/").casefold().removeprefix("./")
            if fnmatch.fnmatchcase(candidate, pattern) or fnmatch.fnmatchcase(name, pattern):
                return True
            prefix = pattern.removesuffix("/**").removesuffix("/*").rstrip("/")
            if directory and (candidate == prefix or candidate.startswith(prefix + "/")) and "*" not in prefix:
                return True
        return False

    def _relative(self, path: Path) -> str:
        try:
            return path.relative_to(self.root).as_posix()
        except ValueError:
            return path.name

    def _error(self, path: Path, phase: str, exc: BaseException) -> ScanError:
        return ScanError(self._relative(path), phase, f"{exc.__class__.__name__}: {exc}")


def scan(config: ScanConfig) -> ScanResult:
    started = time.perf_counter()
    root = config.root.resolve()
    if not root.is_dir():
        raise ValueError(f"scan path is not a directory: {root}")
    discovery = RepositoryDiscovery(config)
    files = discovery.run()
    result = ScanResult(
        metadata={
            "platform": "Windows" if os.name == "nt" else platform.system(),
            "root": str(root),
            "files_discovered": discovery.discovered,
            "files_analyzed": discovery.analyzed,
            "files_skipped": discovery.discovered - discovery.analyzed,
            "languages": sorted({item.language for item in files} | {item.language for item in discovery.binaries}),
            "frameworks": detect_frameworks(files),
            "offline": config.offline,
            "network_access": "ENABLED" if config.cve and not config.offline else "DISABLED",
        },
        errors=list(discovery.errors),
    )
    if not 1 <= config.workers <= 8:
        raise ValueError("workers must be between 1 and 8")
    _analyze_files(files, result, config.workers)
    def analyze_one_binary(binary: BinaryFile):
        try:
            return analyze_binary(binary.relative, binary.data), []
        except Exception as exc:
            return [], [ScanError(binary.relative, "binary-analysis", f"{exc.__class__.__name__}: {exc}")]
    if config.workers > 1 and len(discovery.binaries) > 1:
        with ThreadPoolExecutor(max_workers=config.workers) as executor:
            binary_results = list(executor.map(analyze_one_binary, discovery.binaries))
    else:
        binary_results = [analyze_one_binary(binary) for binary in discovery.binaries]
    for findings, errors in binary_results:
        result.findings.extend(findings)
        result.errors.extend(errors)
    for finding in result.findings:
        enrich_finding(finding)
    _dependencies(config, root, discovery.manifests, result)
    suppressions = suppression_index(files)
    if suppressions:
        result.findings = [item for item in result.findings if not is_suppressed(item, suppressions)]
    minimum = SEVERITY_RANK[config.min_severity]
    result.findings = [item for item in result.findings if SEVERITY_RANK[item.severity] <= minimum]
    if config.remote_only:
        result.findings = [item for item in result.findings if has_remote_source(item)]
    if config.attack_surface:
        result.metadata["attack_surface"] = map_attack_surface(files, result.findings)
    result.normalize()
    result.metadata["scan_duration"] = round(time.perf_counter() - started, 6)
    return result


def _analyze_files(files: list[SourceFile], result: ScanResult, workers: int = 1) -> None:
    imported_sinks = imported_sink_map(files)
    python_sources = [(item.relative, item.text) for item in files if item.language == "Python"]
    if python_sources:
        project = PythonProject(python_sources)
        result.findings.extend(project.analyze())
        result.errors.extend(project.errors)
        for relative, code in python_sources:
            try:
                result.findings.extend(analyze_argument_injection(relative, code))
                result.findings.extend(analyze_tar_extraction(relative, code))
                result.findings.extend(analyze_timing_comparisons(relative, code))
                result.findings.extend(analyze_route_authz(relative, code))
            except Exception as exc:
                result.errors.append(ScanError(relative, "python-arguments", f"{exc.__class__.__name__}: {exc}"))
    def analyze_one(source: SourceFile):
        if source.language in _CODE_ANALYSIS_SKIP:
            return [], []
        found = []
        try:
            found.extend(lexical_findings(source.path.name, source.relative, source.language, source.text))
            if source.language in {"JavaScript", "TypeScript"}:
                found.extend(analyze_javascript(
                    source.relative, source.text, source.language,
                    imported_sinks.get(source.relative),
                ))
                found.extend(analyze_javascript_timing(source.relative, source.text, source.language))
            elif source.language in CATALOGS:
                found.extend(analyze_structured(source.relative, source.text, source.language))
            if source.language == "Java":
                found.extend(analyze_java_zip_slip(source.relative, source.text))
            if source.language == "Go":
                found.extend(analyze_go_zip_slip(source.relative, source.text))
            return found, []
        except Exception as exc:
            return found, [ScanError(source.relative, "analysis", f"{exc.__class__.__name__}: {exc}")]

    if workers > 1 and len(files) > 1:
        # executor.map preserves discovery order irrespective of completion order.
        with ThreadPoolExecutor(max_workers=workers) as executor:
            results = list(executor.map(analyze_one, files))
    else:
        results = [analyze_one(source) for source in files]
    for findings, errors in results:
        result.findings.extend(findings)
        result.errors.extend(errors)


def _dependencies(config: ScanConfig, root: Path, manifests: list[Path], result: ScanResult) -> None:
    dependencies, errors = scan_dependencies(root, manifests)
    result.dependencies = dependencies
    result.errors.extend(errors)
    if not config.cve:
        return
    from .cve import OSVClient

    client = OSVClient(offline=config.offline, local_db=config.cve_db, cache_path=config.cve_cache)
    result.dependency_vulnerabilities = client.query(result.dependencies)
    result.errors.extend(ScanError("", "cve", message) for message in client.errors)


def scan_path(root: Path | str, **kwargs: object) -> ScanResult:
    return scan(ScanConfig(root=Path(root), **kwargs))


def classify_name(name: str) -> str | None:
    lowered = name.casefold()
    if lowered.startswith(".env"):
        return "Environment"
    if lowered in _SPECIAL_NAMES:
        return _SPECIAL_NAMES[lowered]
    if lowered.startswith("dockerfile.") or lowered.endswith(".dockerfile"):
        return "Dockerfile"
    suffix = os.path.splitext(lowered)[1]
    return LANGUAGE_EXTENSIONS.get(suffix)


def classify_shebang(head: bytes) -> str | None:
    if not head.startswith(b"#!"):
        return None
    first = head.split(b"\n", 1)[0].decode("utf-8", errors="replace").casefold()
    if "python" in first:
        return "Python"
    if "pwsh" in first or "powershell" in first:
        return "PowerShell"
    if "node" in first or "deno" in first or "bun" in first:
        return "JavaScript"
    if "ruby" in first:
        return "Ruby"
    if any(shell in first for shell in ("/sh", "bash", "zsh", "dash", "ksh")):
        return "Shell"
    return None


def detect_frameworks(files: Iterable[SourceFile]) -> list[str]:
    probes = {
        "Flask": ("from flask", "import flask", "Flask("),
        "Django": ("from django", "import django", "DJANGO_SETTINGS_MODULE"),
        "FastAPI": ("from fastapi", "import fastapi", "FastAPI("),
        "Express": ('"express"', "require('express')", 'require("express")', "from 'express'"),
        "Next.js": ('"next"', "from 'next", 'from "next'),
        "Laravel": ("Illuminate\\", '"laravel/framework"'),
        "Symfony": ("Symfony\\Component", '"symfony/framework-bundle"'),
        "Spring": ("org.springframework", "@SpringBootApplication"),
        "ASP.NET Core": ("Microsoft.AspNetCore", "WebApplication.CreateBuilder"),
        "Gin": ("github.com/gin-gonic/gin",),
        "Echo": ("github.com/labstack/echo",),
        "Rails": ("ActionController", "Rails.application"),
        "net/http": ('"net/http"',),
    }
    frameworks: set[str] = set()
    for source in files:
        for framework, markers in probes.items():
            if framework not in frameworks and any(marker in source.text for marker in markers):
                frameworks.add(framework)
    return sorted(frameworks)


def _is_binary(data: bytes) -> bool:
    sample = data[:8192]
    if not sample:
        return False
    if sample.startswith((b"\xff\xfe", b"\xfe\xff")):
        return False
    if b"\x00" in sample:
        return True
    controls = sum(byte < 9 or 13 < byte < 32 for byte in sample)
    return controls / len(sample) > 0.20
