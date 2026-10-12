from __future__ import annotations

import ast
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1] / "vulcscan"

FORBIDDEN_AI_MARKERS = {
    "openai",
    "anthropic",
    "gemini",
    "ollama",
    "llama.cpp",
    "huggingface",
    "transformers",
}
NETWORK_MODULES = {"socket", "urllib", "http", "httpx", "requests", "aiohttp"}


def test_runtime_package_contains_no_ai_integration_markers() -> None:
    matches: list[str] = []
    for path in sorted(PACKAGE.glob("*.py")):
        text = path.read_text(encoding="utf-8").casefold()
        for marker in FORBIDDEN_AI_MARKERS:
            if marker in text:
                matches.append(f"{path.name}: {marker}")
    assert matches == []


def test_network_capable_imports_are_confined_to_cve_module() -> None:
    offenders: list[str] = []
    for path in sorted(PACKAGE.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            modules: list[str] = []
            if isinstance(node, ast.Import):
                modules.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules.append(node.module)
            for module in modules:
                root = module.split(".", 1)[0]
                if root in NETWORK_MODULES and path.name != "cve.py":
                    offenders.append(f"{path.name}: {module}")
    assert offenders == []
