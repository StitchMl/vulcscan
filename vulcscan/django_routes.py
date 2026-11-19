"""Parse literal Django urlpatterns without importing or executing target modules.

Only a module-level list/tuple of path(...) declarations is supported.
Dynamic URLs, includes, regex routes and unresolved view expressions abstain.
"""
from __future__ import annotations

import ast
from pathlib import PurePosixPath
from typing import Any


def django_routes(relative: str, source: str, available: set[str]) -> list[dict[str, Any]]:
    if PurePosixPath(relative).name != "urls.py":
        return []
    try:
        tree = ast.parse(source, filename=relative)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return []

    path_names = set()
    view_aliases: dict[str, str] = {}
    view_modules: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.ImportFrom):
            if node.module == "django.urls":
                path_names.update(alias.asname or alias.name for alias in node.names if alias.name == "path")
            elif node.level == 1 and node.module in {"views", None}:
                for alias in node.names:
                    if node.module == "views":
                        view_aliases[alias.asname or alias.name] = alias.name
                    elif alias.name == "views":
                        view_modules[alias.asname or alias.name] = "views"
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "django.urls":
                    path_names.add((alias.asname or "django") + ".urls.path")

    if not path_names:
        return []

    def handler(expression: ast.AST) -> tuple[str, str, bool] | None:
        auth = False
        if (
            isinstance(expression, ast.Call)
            and isinstance(expression.func, ast.Name)
            and expression.func.id in {"login_required", "permission_required"}
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
                expression = expression.func.value
            else:
                return None
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

    folder = PurePosixPath(relative).parent
    routes = []
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if not any(isinstance(target, ast.Name) and target.id == "urlpatterns" for target in targets):
            continue
        array = node.value
        if not isinstance(array, (ast.List, ast.Tuple)):
            continue
        for entry in array.elts:
            if not isinstance(entry, ast.Call) or len(entry.args) < 2:
                continue
            func = entry.func
            allowed = (
                isinstance(func, ast.Name) and func.id in path_names
                or isinstance(func, ast.Attribute)
                and ast.unparse(func) in path_names
            )
            if not allowed:
                continue
            literal, view = entry.args[:2]
            if not isinstance(literal, ast.Constant) or not isinstance(literal.value, str):
                continue
            route = literal.value
            if route.startswith("/") or any(ord(c) < 32 for c in route):
                continue
            resolved = handler(view)
            if resolved is None:
                continue
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
            routes.append(item)
    return routes
