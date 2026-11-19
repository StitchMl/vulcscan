from __future__ import annotations

from pathlib import Path

from vulcscan.scanner import scan_path


def _routes(root: Path, code: str):
    (root / "server.go").write_text(code, encoding="utf-8")
    result = scan_path(root, cve=False, attack_surface=True)
    return result.metadata["attack_surface"]


def test_gin_literal_route_inventory(tmp_path: Path) -> None:
    routes = _routes(
        tmp_path,
        'package main\n'
        'import "github.com/gin-gonic/gin"\n'
        'func setup() {\n'
        ' r := gin.Default()\n'
        ' r.GET("/users/:id", getUser)\n'
        ' r.POST("/users", createUser)\n'
        '}\n',
    )
    assert [(r["method"], r["path"], r["handler"]) for r in routes] == [
        (["GET"], "/users/:id", "getUser"),
        (["POST"], "/users", "createUser"),
    ]
    assert routes[0]["file"] == "server.go"
    assert routes[0]["line"] == 5
    assert routes[0]["authentication"] == "unknown"


def test_gin_auth_middleware_detected_when_explicit(tmp_path: Path) -> None:
    routes = _routes(
        tmp_path,
        'package main\n'
        'import "github.com/gin-gonic/gin"\n'
        'func setup() {\n'
        ' router := gin.New()\n'
        ' router.GET("/admin", requireAuth, admin)\n'
        '}\n',
    )
    assert len(routes) == 1
    assert routes[0]["authentication"] == "present"
    assert routes[0]["handler"] == "admin"


def test_gin_inline_handler_has_unknown_name(tmp_path: Path) -> None:
    routes = _routes(
        tmp_path,
        'package main\n'
        'import "github.com/gin-gonic/gin"\n'
        'func setup() {\n'
        ' engine := gin.Default()\n'
        ' engine.DELETE("/documents/:id", func(c *gin.Context) { c.Status(204) })\n'
        '}\n',
    )
    assert len(routes) == 1
    assert routes[0]["handler"] is None


def test_gin_raw_literal_path_and_any_method(tmp_path: Path) -> None:
    routes = _routes(
        tmp_path,
        'package main\n'
        'import "github.com/gin-gonic/gin"\n'
        'func setup() {\n'
        ' r := gin.Default()\n'
        ' r.Any(' + chr(96) + '/health' + chr(96) + ', health)\n'
        '}\n',
    )
    assert len(routes) == 1
    assert routes[0]["method"] == ["ANY"]
    assert routes[0]["path"] == "/health"


def test_go_route_literals_inside_comments_and_strings_ignored(tmp_path: Path) -> None:
    routes = _routes(
        tmp_path,
        'package main\n'
        'import "github.com/gin-gonic/gin"\n'
        'func setup() {\n'
        ' r := gin.Default()\n'
        ' // r.GET("/not-real", ghost)\n'
        ' /* r.POST("/also-fake", ghost) */\n'
        ' s := "r.DELETE(\\"/fake\\", ghost)"\n'
        ' _ = s\n'
        '}\n',
    )
    assert routes == []


def test_dynamic_path_and_non_gin_code_ignored(tmp_path: Path) -> None:
    routes = _routes(
        tmp_path,
        'package main\n'
        'func setup() {\n'
        ' r.GET(pathVariable, handler)\n'
        ' r.GET("/would-be-gin", handler)\n'
        '}\n',
    )
    assert routes == []
