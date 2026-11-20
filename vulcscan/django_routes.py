"""Parse literal Django urlpatterns without importing or executing target modules.

Only a module-level list/tuple of path(...) declarations is supported.
Dynamic URLs, includes, regex routes and unresolved view expressions abstain.
"""
from __future__ import annotations

import ast
from pathlib import PurePosixPath
from typing import Any

_AUTH_WRAPPERS = {"login_required", "permission_required"}


def _record_from_import(
    node: ast.ImportFrom,
    path_names: set[str],
    view_aliases: dict[str, str],
    view_modules: dict[str, str],
) -> None:
    if node.module == "django.urls":
        path_names.update(alias.asname or alias.name for alias in node.names if alias.name == "path")
    elif node.level == 1 and node.module in {"views", None}:
        for alias in node.names:
            if node.module == "views":
                view_aliases[alias.asname or alias.name] = alias.name
            elif alias.name == "views":
                view_modules[alias.asname or alias.name] = "views"


def _collect_imports(tree: ast.Module) -> tuple[set[str], dict[str, str], dict[str, str]]:
    path_names: set[str] = set()
    view_aliases: dict[str, str] = {}
    view_modules: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.ImportFrom):
            _record_from_import(node, path_names, view_aliases, view_modules)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "django.urls":
                    path_names.add((alias.asname or "django") + ".urls.path")
    return path_names, view_aliases, view_modules


def _unwrap_view(expression: ast.AST) -> tuple[ast.AST | None, bool]:
    """Strip an auth wrapper and as_view(); return (expression, auth) or (None, auth)."""
    auth = False
    if (
        isinstance(expression, ast.Call)
        and isinstance(expression.func, ast.Name)
        and expression.func.id in _AUTH_WRAPPERS
        and len(expression.args) == 1
    ):
        auth = True
        expression = expression.args[0]
    if isinstance(expression, ast.Call):
        if (
            isinstance(expression.func, ast.Attribute)
            and expression.func.attr == "as_view"
            and not expression.args and not expression.keywords
        ):
            return expression.func.value, auth
        return None, auth
    return expression, auth


def _resolve_handler(
    expression: ast.AST, view_aliases: dict[str, str], view_modules: dict[str, str]
) -> tuple[str, str, bool] | None:
    expression, auth = _unwrap_view(expression)
    if isinstance(expression, ast.Name):
        local = expression.id
        if local in view_aliases:
            return view_aliases[local], "views", auth
        return local, "", auth
    if (
        isinstance(expression, ast.Attribute)
        and isinstance(expression.value, ast.Name)
        and expression.value.id in view_modules
    ):
        return expression.attr, view_modules[expression.value.id], auth
    return None


def _urlpatterns_elements(node: ast.stmt) -> list[ast.expr] | None:
    if not isinstance(node, (ast.Assign, ast.AnnAssign)):
        return None
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    if not any(isinstance(target, ast.Name) and target.id == "urlpatterns" for target in targets):
        return None
    array = node.value
    if not isinstance(array, (ast.List, ast.Tuple)):
        return None
    return array.elts


def _is_path_call(entry: ast.expr, path_names: set[str]) -> bool:
    if not isinstance(entry, ast.Call) or len(entry.args) < 2:
        return False
    func = entry.func
    return bool(
        isinstance(func, ast.Name) and func.id in path_names
        or isinstance(func, ast.Attribute)
        and ast.unparse(func) in path_names
    )


def _literal_route(expression: ast.expr) -> str | None:
    if not isinstance(expression, ast.Constant) or not isinstance(expression.value, str):
        return None
    route = expression.value
    if route.startswith("/") or any(ord(c) < 32 for c in route):
        return None
    return route


def _route_item(
    entry: ast.Call,
    relative: str,
    folder: PurePosixPath,
    available: set[str],
    path_names: set[str],
    view_aliases: dict[str, str],
    view_modules: dict[str, str],
) -> dict[str, Any] | None:
    if not _is_path_call(entry, path_names):
        return None
    literal, view = entry.args[:2]
    route = _literal_route(literal)
    if route is None:
        return None
    resolved = _resolve_handler(view, view_aliases, view_modules)
    if resolved is None:
        return None
    name, module, auth = resolved
    item: dict[str, Any] = {
        "method": ["ANY"],
        "path": "/" + route,
        "file": relative,
        "line": entry.lineno,
        "handler": name,
        "authentication": "present" if auth else "unknown",
    }
    if module:
        target = str(folder / (module + ".py"))
        if target in available:
            item["handler_file"] = target
        else:
            # Do not imply that a missing view module has a known handler.
            item["handler"] = None
    return item


def django_routes(relative: str, source: str, available: set[str]) -> list[dict[str, Any]]:
    if PurePosixPath(relative).name != "urls.py":
        return []
    try:
        tree = ast.parse(source, filename=relative)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return []

    path_names, view_aliases, view_modules = _collect_imports(tree)
    if not path_names:
        return []

    folder = PurePosixPath(relative).parent
    routes = []
    for node in tree.body:
        elements = _urlpatterns_elements(node)
        for entry in elements or ():
            item = _route_item(entry, relative, folder, available, path_names, view_aliases, view_modules)
            if item is not None:
                routes.append(item)
    return routes
