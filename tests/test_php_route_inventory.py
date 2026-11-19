from __future__ import annotations

from pathlib import Path

from vulcscan.scanner import scan_path


def _routes(root: Path, code: str):
    (root / "web.php").write_text(code, encoding="utf-8")
    return scan_path(root, cve=False, attack_surface=True).metadata["attack_surface"]


def test_laravel_routes_with_literal_paths_and_controller_actions(tmp_path: Path) -> None:
    result = _routes(tmp_path,
        "<?php\n"
        "Route::get('/users/{id}', [UserController::class, 'show']);\n"
        "Route::post('/users', [UserController::class, 'store']);\n",
    )
    assert [(x["method"], x["path"], x["handler"]) for x in result] == [
        (["GET"], "/users/{id}", "UserController.show"),
        (["POST"], "/users", "UserController.store"),
    ]
    assert result[0]["line"] == 2


def test_laravel_legacy_action_and_auth_middleware(tmp_path: Path) -> None:
    result = _routes(tmp_path,
        "<?php\n"
        "Route::delete('/admin/{id}', 'AdminController@destroy')->middleware('auth');\n",
    )
    assert len(result) == 1
    assert result[0]["handler"] == "AdminController.destroy"
    assert result[0]["authentication"] == "present"


def test_laravel_closure_has_no_guessed_handler(tmp_path: Path) -> None:
    result = _routes(tmp_path,
        "<?php\n"
        "Route::get('/health', function () { return 'ok'; });\n",
    )
    assert len(result) == 1
    assert result[0]["handler"] is None


def test_slim_app_routes(tmp_path: Path) -> None:
    result = _routes(tmp_path,
        "<?php\n"
        "use Slim\\Factory\\AppFactory;\n"
        "$app = AppFactory::create();\n"
        "$app->get('/items', listItems);\n",
    )
    assert len(result) == 1
    assert result[0]["method"] == ["GET"]
    assert result[0]["handler"] == "listItems"


def test_slim_route_without_framework_evidence_is_ignored(tmp_path: Path) -> None:
    assert not _routes(tmp_path,
        "<?php\n"
        "$app->get('/may-not-be-slim', handler);\n",
    )


def test_dynamic_path_is_not_mapped(tmp_path: Path) -> None:
    result = _routes(tmp_path,
        "<?php\n"
        "Route::get($userRoute, [UserController::class, 'show']);\n",
    )
    assert not result


def test_comments_and_quoted_route_text_are_not_routes(tmp_path: Path) -> None:
    result = _routes(tmp_path,
        "<?php\n"
        "// Route::get('/fake', [UserController::class, 'show']);\n"
        "/* Route::post('/fake2', [UserController::class, 'store']); */\n"
        '$text = "Route::delete(\'/fake3\', \'UserController@destroy\')";' + "\n",
    )
    assert not result


def test_other_framework_routes_not_guessed(tmp_path: Path) -> None:
    result = _routes(tmp_path,
        "<?php\n"
        "$api->get('/hello', handler);\n"
        "Other::get('/hello', handler);\n",
    )
    assert not result
