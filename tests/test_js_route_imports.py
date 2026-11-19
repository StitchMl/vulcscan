from __future__ import annotations

from pathlib import Path

from vulcscan.js_routes import resolve_handler
from vulcscan.scanner import scan_path


def test_esmodule_handler_is_linked_to_route_and_finding(tmp_path: Path) -> None:
    (tmp_path / "routes.js").write_text(
        "import { search as findItems } from './controllers.js';\n"
        "app.get('/items', findItems);\n",
        encoding="utf-8",
    )
    (tmp_path / "controllers.js").write_text(
        "const cp = require('child_process');\n"
        "export function search(req, res) {\n"
        "  const query = req.query.cmd;\n"
        "  cp.exec(query);\n"
        "}\n",
        encoding="utf-8",
    )
    result = scan_path(tmp_path, cve=False, attack_surface=True)
    route = next(x for x in result.metadata["attack_surface"] if x["path"] == "/items")
    assert route["handler_file"] == "controllers.js"
    assert route["finding_rules"] == ["JS-CMD-001"]


def test_commonjs_destructured_handler_is_linked(tmp_path: Path) -> None:
    (tmp_path / "routes.js").write_text(
        "const { search: findItems } = require('./controller');\n"
        "router.get('/items', findItems);\n",
        encoding="utf-8",
    )
    (tmp_path / "controller.js").write_text(
        "const cp = require('child_process');\n"
        "function search(req, res) {\n"
        "  cp.exec(req.query.cmd);\n"
        "}\n"
        "module.exports = { search };\n",
        encoding="utf-8",
    )
    result = scan_path(tmp_path, cve=False, attack_surface=True)
    route = next(x for x in result.metadata["attack_surface"] if x["path"] == "/items")
    assert route["handler_file"] == "controller.js"
    assert "JS-CMD-001" in route["finding_rules"]


def test_unimported_handler_cannot_claim_unrelated_findings(tmp_path: Path) -> None:
    (tmp_path / "routes.js").write_text(
        "app.get('/items', search);\n", encoding="utf-8",
    )
    (tmp_path / "other.js").write_text(
        "const cp = require('child_process');\n"
        "function search(req, res) { cp.exec(req.query.cmd); }\n",
        encoding="utf-8",
    )
    result = scan_path(tmp_path, cve=False, attack_surface=True)
    route = next(x for x in result.metadata["attack_surface"] if x["path"] == "/items")
    assert "handler_file" not in route
    assert route["finding_rules"] == []


def test_import_outside_repository_is_not_resolved() -> None:
    assert resolve_handler(
        "routes.js",
        "import { search } from '../private.js';\n",
        "search",
        {"routes.js": object(), "../private.js": object()},
    ) is None


def test_ambiguous_extension_is_not_guessed(tmp_path: Path) -> None:
    class Source:
        def __init__(self, text: str) -> None:
            self.text = text

    modules = {
        "routes.js": Source("import { search } from './controller';"),
        "controller.js": Source("export function search(req) {}"),
        "controller.ts": Source("export function search(req) {}"),
    }
    assert resolve_handler("routes.js", modules["routes.js"].text, "search", modules) is None


def test_default_scan_schema_does_not_change(tmp_path: Path) -> None:
    (tmp_path / "routes.js").write_text("app.get('/items', search);\n", encoding="utf-8")
    result = scan_path(tmp_path, cve=False)
    assert "attack_surface" not in result.metadata
