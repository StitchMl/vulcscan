"""Bounded multi-hop summaries for imported JavaScript/TypeScript sinks.

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
_RELAY_CALL = re.compile(
    r"^\s*(?:return\s+)?(?:await\s+)?([A-Za-z_$][\w$]*)\s*"
    r"\(\s*([A-Za-z_$][\w$]*(?:\s*,\s*[A-Za-z_$][\w$]*)*)\s*\)\s*;?\s*$"
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


def _required_module_sinks(source: str, names: dict[str, tuple[str, str]]) -> None:
    for match in _REQUIRE.finditer(source):
        alias, module = match.groups()
        kind = "child_process" if module == "child_process" else "fs"
        methods = {"exec": "JS-CMD-001", "execSync": "JS-CMD-001"} if kind == "child_process" else {"readFile": "JS-PATH-001", "readFileSync": "JS-PATH-001"}
        for method, rule in methods.items():
            names[alias + "." + method] = (rule, alias + "." + method)


_IMPORT_ENTRY = re.compile(r"\s*([A-Za-z_$][\w$]*)(?:\s+as\s*([A-Za-z_$][\w$]*))?\s*")
_REQUIRE_ENTRY = re.compile(r"\s*([A-Za-z_$][\w$]*)(?:\s+:\s*([A-Za-z_$][\w$]*))?\s*")


def _module_sink_rule(module: str, exported: str) -> str | None:
    if module == "child_process" and exported in {"exec", "execSync"}:
        return "JS-CMD-001"
    if module in {"fs", "fs/promises"} and exported in {"readFile", "readFileSync"}:
        return "JS-PATH-001"
    return None


def _named_module_sinks(source: str, names: dict[str, tuple[str, str]]) -> None:
    for match in list(_NAMED_IMPORT.finditer(source)) + list(_NAMED_REQUIRE.finditer(source)):
        entries, module = match.groups()
        entry_pattern = _REQUIRE_ENTRY if match.re is _NAMED_REQUIRE else _IMPORT_ENTRY
        for entry in entries.split(","):
            parts = entry_pattern.fullmatch(entry)
            if not parts:
                continue
            exported, local = parts.group(1), parts.group(2) or parts.group(1)
            rule_id = _module_sink_rule(module, exported)
            if rule_id is not None:
                names[local] = (rule_id, exported)


def _safe_sink_names(source: str) -> dict[str, tuple[str, str]]:
    names: dict[str, tuple[str, str]] = {"eval": ("JS-CODE-001", "eval"), "fetch": ("JS-SSRF-001", "fetch")}
    _required_module_sinks(source, names)
    _named_module_sinks(source, names)
    return names


def _direct_sink_uses_parameter(
    direct: re.Match[str] | None,
    names: dict[str, tuple[str, str]],
    parameters: list[str],
) -> bool:
    """A parameter named like a sink shadows that sink in the wrapper body."""
    return bool(
        direct
        and direct.group(1) in names
        and direct.group(1) not in parameters
        and direct.group(2) in parameters
    )


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
        if not _direct_sink_uses_parameter(direct, names, names_list):
            continue
        rule, sink = names[direct.group(1)]
        result[function] = ImportedSink(rule, names_list.index(direct.group(2)), path, text.count("\n", 0, match.end()) + 1, sink)
    return {name: summary for name, summary in result.items() if occurrences[name] == 1}


def _import_aliases(clean: str) -> set[str]:
    aliases: set[str] = set()
    for matched in _IMPORTS.finditer(clean):
        members = matched.group(1) or matched.group(2) or ""
        for part in members.split(","):
            symbol = re.search(r"([A-Za-z_$][\w$]*)\s*$", part)
            if symbol:
                aliases.add(symbol.group(1))
    return aliases


def _is_shadowed(clean: str, alias: str) -> bool:
    # An imported identifier shadowed by a local declaration or function
    # parameter cannot safely be treated as the imported binding.
    escaped = re.escape(alias)
    return bool(re.search(
        rf"\b(?:function|class)\s+{escaped}\b|"
        rf"\b(?:function|catch)\s*(?:[A-Za-z_$][\w$]*)?\s*\([^)]*\b{escaped}\b",
        clean,
    ))


def _alias_summary(
    path: str, clean: str, alias: str, modules: dict[str, Any], summaries: dict[str, dict[str, ImportedSink]]
) -> ImportedSink | None:
    if _is_shadowed(clean, alias):
        return None
    imported = _named_import(clean, alias)
    if imported is None:
        return None
    specifier, exported = imported
    destination = _module_path(path, specifier, set(modules))
    if destination is None or destination == path:
        return None
    return summaries[destination].get(exported)


def _relay_from_call(
    path: str,
    clean: str,
    body: str,
    parameters: list[str],
    imports: set[str],
    modules: dict[str, Any],
    summaries: dict[str, dict[str, ImportedSink]],
) -> ImportedSink | None:
    call = _RELAY_CALL.fullmatch(body)
    if call is None or call.group(1) not in imports:
        return None
    sink = _alias_summary(path, clean, call.group(1), modules, summaries)
    if sink is None:
        return None
    arguments = [part.strip() for part in call.group(2).split(",")]
    if sink.parameter_index >= len(arguments):
        return None
    tainted = arguments[sink.parameter_index]
    if tainted not in parameters:
        return None
    return ImportedSink(
        sink.rule_id, parameters.index(tainted), sink.file, sink.line, sink.sink
    )


def _relay_summaries(
    path: str,
    source: str,
    modules: dict[str, Any],
    direct: dict[str, dict[str, ImportedSink]],
) -> dict[str, ImportedSink]:
    """Summarize an unchanged-argument relay to a previously verified sink."""
    clean = blank_comments(source, JS_STYLE)
    mask = code_mask(source, JS_STYLE)
    imports = _import_aliases(clean)
    occurrences: dict[str, int] = {}
    relays: dict[str, ImportedSink] = {}
    for match in _FUNCTION.finditer(clean):
        name, parameters = match.group(1), match.group(2)
        occurrences[name] = occurrences.get(name, 0) + 1
        if not _exported(clean, name):
            continue
        args = [item.strip() for item in parameters.split(",")]
        if not args or not all(re.fullmatch(r"[A-Za-z_$][\w$]*", arg) for arg in args):
            continue
        end = _matching_brace(mask, match.end() - 1)
        if end < 0:
            continue
        summary = _relay_from_call(
            path, clean, clean[match.end():end], args, imports, modules, direct
        )
        if summary is not None:
            relays[name] = summary
    return {name: sink for name, sink in relays.items() if occurrences[name] == 1}


def imported_sink_map(files: list[Any]) -> dict[str, dict[str, ImportedSink]]:
    """Map caller file -> alias -> strictly bounded imported sink summary."""
    modules = {item.relative: item for item in files if item.language in {"JavaScript", "TypeScript"}}
    summaries = {path: _summaries(path, item.text) for path, item in modules.items()}
    # Extend summaries at most three relay layers beyond direct sinks.
    # Fixed rounds keep analysis bounded even when modules import cyclically.
    for _ in range(3):
        relays = {
            path: _relay_summaries(path, item.text, modules, summaries)
            for path, item in modules.items()
        }
        summaries = {path: {**summaries[path], **relays[path]} for path in modules}
    result: dict[str, dict[str, ImportedSink]] = {}
    for path, item in modules.items():
        clean = blank_comments(item.text, JS_STYLE)
        targets: dict[str, ImportedSink] = {}
        for alias in _import_aliases(clean):
            summary = _alias_summary(path, clean, alias, modules, summaries)
            if summary is not None:
                targets[alias] = summary
        if targets:
            result[path] = targets
    return result
