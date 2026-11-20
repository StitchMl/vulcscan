from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from . import __version__
from .models import ScanConfig, Severity
from .report import render_json, render_text, render_unified_diff, write_report
from .scanner import RepositoryDiscovery, scan

_SIZE_UNITS = {
    "": 1,
    "B": 1,
    "K": 1_000,
    "KB": 1_000,
    "KIB": 1_024,
    "M": 1_000_000,
    "MB": 1_000_000,
    "MIB": 1_048_576,
    "G": 1_000_000_000,
    "GB": 1_000_000_000,
    "GIB": 1_073_741_824,
}


def parse_size(value: str) -> int:
    text = value.strip().upper().replace(" ", "")
    number_end = 0
    dot_seen = False
    for character in text:
        if character.isdigit():
            number_end += 1
            continue
        if character == "." and not dot_seen:
            dot_seen = True
            number_end += 1
            continue
        break
    number_text = text[:number_end]
    unit = text[number_end:]
    if not number_text or number_text == "." or unit not in _SIZE_UNITS:
        raise argparse.ArgumentTypeError(
            "size must be a positive number with B, KB, KiB, MB, MiB, GB, or GiB"
        )
    try:
        size = float(number_text) * _SIZE_UNITS[unit]
    except ValueError as exc:
        raise argparse.ArgumentTypeError("invalid size") from exc
    if size < 1 or size > sys.maxsize:
        raise argparse.ArgumentTypeError("size must be greater than zero")
    return int(size)


def parse_severity(value: str) -> Severity:
    try:
        return Severity(value.upper())
    except ValueError as exc:
        choices = ", ".join(item.value for item in Severity)
        raise argparse.ArgumentTypeError(f"severity must be one of: {choices}") from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulcscan",
        description="Deterministic static application security scanner.",
    )
    parser.add_argument("path", type=Path, help="repository or source directory to scan")
    parser.add_argument(
        "--offline",
        action="store_true",
        help="keep network disabled (the default); dependency CVEs require --cve-db",
    )
    parser.add_argument(
        "--update-cve",
        action="store_true",
        help="query OSV for this scan; results are kept only in memory",
    )
    parser.add_argument(
        "--cve-db",
        type=Path,
        metavar="FILE",
        help="read an explicit local OSV snapshot JSON file; network remains disabled",
    )
    parser.add_argument(
        "--cve-cache",
        type=Path,
        metavar="FILE",
        help="read an existing OSV cache offline; with --update-cve, create or refresh it after a complete query",
    )
    parser.add_argument("--output", type=Path, help="write the report to this file")
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default=None,
        help="report format; defaults to JSON for a .json output file, text otherwise",
    )
    parser.add_argument(
        "--severity",
        type=parse_severity,
        default=Severity.INFO,
        metavar="LEVEL",
        help="minimum finding severity: CRITICAL, HIGH, MEDIUM, LOW, or INFO",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        metavar="N",
        help="analyze independent files with 1-8 workers (default 1); ordered results",
    )
    parser.add_argument(
        "--exclude-tests",
        action="store_true",
        help="skip common test and fixture directories and test source files (opt-in)",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="PATTERN",
        help="exclude a glob pattern; repeat the option for multiple patterns",
    )
    parser.add_argument(
        "--attack-surface",
        action="store_true",
        help="include a conservative static endpoint inventory in report metadata",
    )
    parser.add_argument(
        "--remote-only",
        action="store_true",
        help="show only findings with identifiable network or HTTP input sources",
    )
    parser.add_argument(
        "--files",
        action="append",
        metavar="PATH",
        help="scan only this repository-relative file; repeat for multiple files",
    )
    parser.add_argument(
        "--max-file-size",
        type=parse_size,
        default=2 * 1024 * 1024,
        metavar="SIZE",
        help="maximum source file size, such as 500KB or 2MiB",
    )
    parser.add_argument(
        "--no-cve",
        action="store_true",
        help="skip dependency vulnerability lookup",
    )
    parser.add_argument(
        "--patch-preview",
        dest="patch_preview",
        action="store_true",
        default=True,
        help="include deterministic current and suggested snippets in text output (default)",
    )
    parser.add_argument(
        "--no-patch-preview",
        dest="patch_preview",
        action="store_false",
        help="hide current and suggested code snippets in text output",
    )
    parser.add_argument(
        "--generate-diff",
        type=Path,
        metavar="FILE",
        help="write verified machine-applicable changes as a unified diff",
    )
    parser.add_argument(
        "--color",
        choices=("auto", "always", "never"),
        default="auto",
        help="color text output: auto for a terminal, always, or never",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def _report_format(requested: str | None, output: Path | None) -> str:
    if requested:
        return requested
    if output and output.suffix.casefold() == ".json":
        return "json"
    return "text"


def _write_stdout(content: str) -> None:
    try:
        sys.stdout.write(content)
    except UnicodeEncodeError:
        encoding = sys.stdout.encoding or "utf-8"
        data = content.encode(encoding, errors="replace")
        sys.stdout.buffer.write(data)


def _error(message: str) -> None:
    print(f"vulcscan: error: {message}", file=sys.stderr)


def _enable_windows_virtual_terminal() -> bool:
    if os.name != "nt":
        return True
    try:
        import ctypes
        import msvcrt

        handle = msvcrt.get_osfhandle(sys.stdout.fileno())
        mode = ctypes.c_ulong()
        kernel32 = ctypes.windll.kernel32
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except (AttributeError, OSError, ValueError):
        return False


def _use_color(mode: str, output: Path | None, report_format: str) -> bool:
    if report_format != "text":
        return False
    if mode == "never":
        return False
    if mode == "always":
        _enable_windows_virtual_terminal()
        return True
    if os.environ.get("NO_COLOR") is not None:
        return False
    return output is None and sys.stdout.isatty() and _enable_windows_virtual_terminal()


def _option_error(args: argparse.Namespace) -> str | None:
    if args.workers < 1 or args.workers > 8:
        return "--workers must be an integer between 1 and 8"
    if args.offline and args.update_cve:
        return "--offline and --update-cve cannot be used together"
    if args.cve_db and args.update_cve:
        return "--cve-db and --update-cve cannot be used together"
    if args.cve_db and args.cve_cache:
        return "--cve-db and --cve-cache cannot be combined"
    if args.cve_cache and args.no_cve:
        return "--cve-cache and --no-cve cannot be combined"
    if args.cve_db and args.no_cve:
        return "--cve-db and --no-cve cannot be used together"
    return None


def _normalize_file_selection(supplied: str) -> str | None:
    """Return a clean repository-relative path, or None when it is unsafe."""
    normalized = supplied.replace(chr(92), "/")
    parts = normalized.split("/")
    if (
        not normalized
        or normalized.startswith("/")
        or any(part == ".." for part in parts)
        or ":" in parts[0]
        or not any(part not in ("", ".") for part in parts)
    ):
        return None
    return "/".join(part for part in parts if part not in ("", "."))


def _select_files(files: Sequence[str]) -> tuple[frozenset[str] | None, str | None]:
    """Return (selection, rejected path); the selection is None when no files were given."""
    if not files:
        return None, None
    selected: set[str] = set()
    for supplied in files:
        clean = _normalize_file_selection(supplied)
        if clean is None:
            return None, supplied
        selected.add(clean)
    return frozenset(selected), None



def _invalid_selected_file(root: Path, selected: frozenset[str] | None) -> str | None:
    """Reject missing, non-regular, or symlinked selected paths before scanning."""
    for relative in sorted(selected or ()):
        path = root.joinpath(*relative.split("/"))
        try:
            if path.resolve(strict=True) != path or not path.is_file():
                return relative
        except (OSError, RuntimeError):
            return relative
    return None



def _selected_files_or_error(
    root: Path, files: Sequence[str]
) -> tuple[frozenset[str] | None, str | None]:
    selected, rejected = _select_files(files)
    if rejected is not None:
        return None, f"--files requires repository-relative file paths: {rejected}"
    invalid = _invalid_selected_file(root, selected)
    if invalid is not None:
        return None, f"--files path is not a regular file within the repository: {invalid}"
    return selected, None



def _ensure_selected_files_included(config: ScanConfig) -> None:
    """Avoid successful empty rescans when an explicit file is excluded."""
    if config.only_files is None:
        return
    discovery = RepositoryDiscovery(config)
    for relative in sorted(config.only_files):
        parts = relative.split("/")
        excluded_parent = any(
            discovery._excluded_directory(part, "/".join(parts[:index + 1]))
            for index, part in enumerate(parts[:-1])
        )
        if excluded_parent or discovery._excluded_file(relative):
            raise ValueError(f"--files selection is excluded by scan options: {relative}")


def _write_outputs(
    result: Any, root: Path, severity: Any, content: str, output: Path | None, diff_path: Path | None
) -> None:
    if output is None:
        _write_stdout(content)
    else:
        write_report(output, content)
        print(f"vulcscan: report written to {output}", file=sys.stderr)
    if diff_path is not None:
        diff = render_unified_diff(result, root, severity)
        write_report(diff_path, diff)
        if not diff:
            print(
                "vulcscan: no verified machine-applicable patch was available",
                file=sys.stderr,
            )


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    root = args.path.expanduser()
    try:
        root = root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        _error(f"cannot access scan path {args.path}: {exc}")
        return 2
    if not root.is_dir():
        _error(f"scan path is not a directory: {root}")
        return 2
    option_error = _option_error(args)
    if option_error is not None:
        _error(option_error)
        return 2

    report_format = _report_format(args.format, args.output)
    output = args.output.expanduser().resolve() if args.output else None
    diff_path = args.generate_diff.expanduser().resolve() if args.generate_diff else None
    if output is not None and diff_path is not None and output == diff_path:
        _error("--output and --generate-diff must name different files")
        return 2

    only_files, selection_error = _selected_files_or_error(root, args.files)
    if selection_error is not None:
        _error(selection_error)
        return 2

    config = ScanConfig(
        root=root,
        offline=not args.update_cve,
        cve=not args.no_cve,
        output=output,
        format=report_format,
        min_severity=args.severity,
        excludes=tuple(args.exclude),
        max_file_size=args.max_file_size,
        patch_preview=args.patch_preview,
        generate_diff=diff_path,
        only_files=only_files,
        attack_surface=args.attack_surface,
        remote_only=args.remote_only,
        exclude_tests=args.exclude_tests,
        workers=args.workers,
        cve_db=args.cve_db.expanduser() if args.cve_db else None,
        cve_cache=args.cve_cache.expanduser() if args.cve_cache else None,
    )
    try:
        _ensure_selected_files_included(config)
        result = scan(config)
    except KeyboardInterrupt:
        _error("scan interrupted")
        return 130
    except Exception as exc:
        _error(str(exc))
        return 2

    if report_format == "json":
        content = render_json(result, args.severity)
    else:
        content = render_text(
            result,
            args.severity,
            patch_preview=args.patch_preview,
            color=_use_color(args.color, output, report_format),
        )

    try:
        _write_outputs(result, root, args.severity, content, output, diff_path)
    except OSError as exc:
        _error(f"cannot write output: {exc}")
        return 2
    return 0
