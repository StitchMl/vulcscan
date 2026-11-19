"""Bounded one-hop summaries for directly imported JavaScript/TypeScript sinks.

Recognize only exported functions whose entire body is one direct sink call of
an unchanged parameter. This intentionally omits transforms, guards, branches,
higher-order calls, default exports, namespace imports and re-exports.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .js_routes import _module_path, _named_import, _exported
from .source import JS_STYLE, blank_comments, code_mask


@dataclass(frozen=True, slots=True)
class ImportedSink:
    rule_id: str
    parameter_index: int
    file: str
    line: int
    sink: str


_IMPORTS = re.compile(
    r"""\b(?:import\s*\{([^}]*)\}\s*from\s*['"][^'"]+['"]|"""
    r"""(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\s*\(\s*['"][^'"]+['"]\s*\))"""
)
_FUNCTION = re.compile(r"\b(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(([^()]*)\)\s*\{")
_DIRECT_CALL = re.compile(
    r"^\s*(?:return\s+)?(?:await\s+)?([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?)\s*"
    r"\(\s*([A-Za-z_$][\w$]*)\s*\)\s*;?\s*$"
)
_REQUIRE = re.compile(
    r"""\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*['"](?:node:)?(child_process|fs|fs/promises)['"]\s*\)"""
)
_NAMED_REQUIRE = re.compile(
    r"""\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\s*\(\s*['"](?:node:)?(child_process|fs|fs/promises)['"]\s*\)"""
)
_NAMED_IMPORT = re.compile(
    r"""\bimport\s*\{([^}]*)\}\s*from\s*['"](?:node:)?(child_process|fs|fs/promises)['"]"""
)


def _matching_brace(mask: str, opening: int) -> int:
    depth = 0
    for index in range(opening, len(mask)):
        if mask[index] == "{":
            depth += 1
        elif mask[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    return -1


def _safe_sink_names(source: str) -> dict[str, tuple[str, str]]:
    names: dict[str, tuple[str, str]] = {"eval": ("JS-CODE-001", "eval"), "fetch": ("JS-SSRF-001", "fetch")}
    for match in _REQUIRE.finditer(source):
        alias, module = match.groups()
        kind = "child_process" if module == "child_process" else "fs"
        methods = {"exec": "JS-CMD-001", "execSync": "JS-CMD-001"} if kind == "child_process" else {"readFile": "JS-PATH-001", "readFileSync": "JS-PATH-001"}
        for method, rule in methods.items():
            names[alias + "." + method] = (rule, alias + "." + method)
    for match in list(_NAMED_IMPORT.finditer(source)) + list(_NAMED_REQUIRE.finditer(source)):
        entries, module = match.groups()
        separator = ":" if match.re is _NAMED_REQUIRE else "as"
        for entry in entries.split(","):
            parts = re.fullmatch(r"\s*([A-Za-z_$][\w$]*)(?:\s+" + (r":" if separator == ":" else r"as") + r"\s*([A-Za-z_$][\w$]*))?\s*", entry)
            if not parts:
                continue
            exported, local = parts.group(1), parts.group(2) or parts.group(1)
            if module == "child_process" and exported in {"exec", "execSync"}:
                names[local] = ("JS-CMD-001", exported)
            elif module in {"fs", "fs/promises"} and exported in {"readFile", "readFileSync"}:
                names[local] = ("JS-PATH-001", exported)
    return names


def _summaries(path: str, source: str) -> dict[str, ImportedSink]:
    text = blank_comments(source, JS_STYLE)
    mask = code_mask(source, JS_STYLE)
    names = _safe_sink_names(text)
    result: dict[str, ImportedSink] = {}
    occurrences: dict[str, int] = {}
    for match in _FUNCTION.finditer(text):
        function, parameters = match.group(1), match.group(2)
        occurrences[function] = occurrences.get(function, 0) + 1
        if not _exported(text, function):
            continue
        names_list = [item.strip() for item in parameters.split(",")]
        if not names_list or not all(re.fullmatch(r"[A-Za-z_$][\w$]*", item) for item in names_list):
            continue
        end = _matching_brace(mask, match.end() - 1)
        if end < 0:
            continue
        body = text[match.end():end]
        direct = _DIRECT_CALL.fullmatch(body)
        if not direct or direct.group(1) not in names or direct.group(2) not in names_list:
            continue
        rule, sink = names[direct.group(1)]
        result[function] = ImportedSink(rule, names_list.index(direct.group(2)), path, text.count("\n", 0, match.end()) + 1, sink)
    return {name: summary for name, summary in result.items() if occurrences[name] == 1}


def imported_sink_map(files: list[Any]) -> dict[str, dict[str, ImportedSink]]:
    """Map caller file -> imported alias -> strict one-hop sink summary."""
    modules = {item.relative: item for item in files if item.language in {"JavaScript", "TypeScript"}}
    summaries = {path: _summaries(path, item.text) for path, item in modules.items()}
    result: dict[str, dict[str, ImportedSink]] = {}
    for path, item in modules.items():
        clean = blank_comments(item.text, JS_STYLE)
        aliases: set[str] = set()
        for matched in _IMPORTS.finditer(clean):
            members = matched.group(1) or matched.group(2) or ""
            for part in members.split(","):
                symbol = re.search(r"([A-Za-z_$][\w$]*)\s*$", part)
                if symbol:
                    aliases.add(symbol.group(1))
        targets: dict[str, ImportedSink] = {}
        for alias in aliases:
            # An imported identifier shadowed by a local declaration or function
            # parameter cannot safely be treated as the imported binding.
            escaped = re.escape(alias)
            if re.search(
                rf"\\b(?:function|class)\\s+{escaped}\\b|"
                rf"\\b(?:function|catch)\\s*(?:[A-Za-z_$][\\w$]*)?\\s*\\([^)]*\\b{escaped}\\b",
                clean,
            ):
                continue
            imported = _named_import(clean, alias)
            if imported is None:
                continue
            specifier, exported = imported
            destination = _module_path(path, specifier, set(modules))
            if destination is None or destination == path:
                continue
            summary = summaries[destination].get(exported)
            if summary is not None:
                targets[alias] = summary
        if targets:
            result[path] = targets
    return result
