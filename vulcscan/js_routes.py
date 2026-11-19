"""Conservative, in-memory resolution of direct Express route handler imports.

Only literal, relative module specifiers and directly exported named functions
are linked. This module never touches the filesystem, imports target modules,
or executes application code.
"""
from __future__ import annotations

import posixpath
import re
from typing import Any

_IDENTIFIER = r"[A-Za-z_$][\w$]*"
_EXPORT_NAME = re.compile(r"^[A-Za-z_$][\w$]*$")


def _module_path(caller: str, specifier: str, available: set[str]) -> str | None:
    if not specifier.startswith("./") and not specifier.startswith("../"):
        return None
    relative = posixpath.normpath(posixpath.join(posixpath.dirname(caller), specifier))
    if relative == ".." or relative.startswith("../") or relative.startswith("/"):
        return None
    candidates = [relative]
    if not posixpath.splitext(relative)[1]:
        candidates.extend(relative + ext for ext in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"))
        candidates.extend(relative + "/index" + ext for ext in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"))
    present = sorted(set(candidates).intersection(available))
    return present[0] if len(present) == 1 else None


def _exported(text: str, name: str) -> bool:
    if not _EXPORT_NAME.fullmatch(name):
        return False
    escaped = re.escape(name)
    definitions = (
        rf"\bexport\s+(?:default\s+)?(?:async\s+)?function\s+{escaped}\s*\(",
        rf"\bexport\s+(?:const|let|var)\s+{escaped}\s*=",
        rf"\bexports\s*\.\s*{escaped}\s*=",
        rf"\bmodule\s*\.\s*exports\s*\.\s*{escaped}\s*=",
        rf"\bmodule\s*\.\s*exports\s*=\s*\{{[^}}]*\b{escaped}\b[^}}]*\}}",
        rf"\bexport\s*\{{[^}}]*\b{escaped}\b[^}}]*\}}",
    )
    return any(re.search(pattern, text) for pattern in definitions)


def _named_import(source: str, symbol: str) -> tuple[str, str] | None:
    """Return (specifier, exported symbol) for unambiguous direct imports."""
    candidates: list[tuple[str, str]] = []
    for match in re.finditer(
        r"""\bimport\s*\{([^}]*)\}\s*from\s*['"]([^'"]+)['"]""",
        source,
    ):
        for item in match.group(1).split(","):
            parts = re.fullmatch(r"\s*([\w$]+)(?:\s+as\s+([\w$]+))?\s*", item)
            if parts and (parts.group(2) or parts.group(1)) == symbol:
                candidates.append((match.group(2), parts.group(1)))
    for match in re.finditer(
        r"""\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)""",
        source,
    ):
        for item in match.group(1).split(","):
            parts = re.fullmatch(r"\s*([\w$]+)(?:\s*:\s*([\w$]+))?\s*", item)
            if parts and (parts.group(2) or parts.group(1)) == symbol:
                candidates.append((match.group(2), parts.group(1)))
    return candidates[0] if len(candidates) == 1 else None


def _local_function(source: str, symbol: str) -> bool:
    escaped = re.escape(symbol)
    return bool(re.search(
        rf"\b(?:async\s+)?function\s+{escaped}\s*\(|"
        rf"\b(?:const|let|var)\s+{escaped}\s*=\s*(?:async\s+)?(?:\(|function\b|[\w$]+\s*=>)",
        source,
    ))


def resolve_handler(
    caller: str, source: str, symbol: str, modules: dict[str, Any]
) -> tuple[str, str] | None:
    """Resolve a directly named same-file or once-imported handler.

    The return is (file, handler function name), or None when ambiguous.
    """
    if not _EXPORT_NAME.fullmatch(symbol):
        return None
    if _local_function(source, symbol):
        return (caller, symbol)
    imported = _named_import(source, symbol)
    if imported is None:
        return None
    specifier, exported = imported
    target = _module_path(caller, specifier, set(modules))
    if target is None or target == caller:
        return None
    other = modules[target].text
    if not _exported(other, exported) or not _local_function(other, exported):
        return None
    return (target, exported)
