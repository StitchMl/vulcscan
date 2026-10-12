from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .models import ScanConfig, Severity
from .report import render_json, render_text, render_unified_diff, write_report
from .scanner import scan

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
        help="keep network disabled (the default); an existing CVE cache may still be read",
    )
    parser.add_argument(
        "--update-cve",
        action="store_true",
        help="explicitly allow OSV network access to refresh dependency CVE data",
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
        "--exclude",
        action="append",
        default=[],
        metavar="PATTERN",
        help="exclude a glob pattern; repeat the option for multiple patterns",
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
        help="skip dependency vulnerability lookup, including cached results",
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
    if report_format != "text" or os.environ.get("NO_COLOR") is not None:
        return False
    if mode == "never":
        return False
    if mode == "always":
        _enable_windows_virtual_terminal()
        return True
    return output is None and sys.stdout.isatty() and _enable_windows_virtual_terminal()


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
    if args.offline and args.update_cve:
        _error("--offline and --update-cve cannot be used together")
        return 2

    report_format = _report_format(args.format, args.output)
    output = args.output.expanduser().resolve() if args.output else None
    diff_path = args.generate_diff.expanduser().resolve() if args.generate_diff else None
    if output is not None and diff_path is not None and output == diff_path:
        _error("--output and --generate-diff must name different files")
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
    )
    try:
        result = scan(config)
    except KeyboardInterrupt:
        _error("scan interrupted")
        return 130
    except Exception as exc:  # noqa: BLE001 - CLI boundary for fatal scanner errors.
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
        if output is None:
            _write_stdout(content)
        else:
            write_report(output, content)
            print(f"vulcscan: report written to {output}", file=sys.stderr)
        if diff_path is not None:
            diff = render_unified_diff(result, root, args.severity)
            write_report(diff_path, diff)
            if not diff:
                print(
                    "vulcscan: no verified machine-applicable patch was available",
                    file=sys.stderr,
                )
    except OSError as exc:
        _error(f"cannot write output: {exc}")
        return 2
    return 0
