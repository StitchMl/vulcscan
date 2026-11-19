from __future__ import annotations

from pathlib import Path

from vulcscan.scanner import scan_path


def _routes(root: Path, text: str):
    (root / "UsersController.java").write_text(text, encoding="utf-8")
    return scan_path(root, cve=False, attack_surface=True).metadata["attack_surface"]


def test_spring_literal_controller_prefix_and_method(tmp_path: Path) -> None:
    routes = _routes(tmp_path,
        '@RestController\n'
        '@RequestMapping("/api")\n'
        'public class UsersController {\n'
        '  @GetMapping("/users/{id}")\n'
        '  public String getUser(String id) { return id; }\n'
        '  @PostMapping("/users")\n'
        '  public String createUser() { return "ok"; }\n'
        '}\n',
    )
    assert [(r["method"], r["path"], r["handler"]) for r in routes] == [
        (["GET"], "/api/users/{id}", "getUser"),
        (["POST"], "/api/users", "createUser"),
    ]
    assert routes[0]["line"] == 4
    assert routes[0]["file"] == "UsersController.java"


def test_spring_pre_authorize_on_handler(tmp_path: Path) -> None:
    routes = _routes(tmp_path,
        '@RestController\n'
        'public class ProfileController {\n'
        '  @GetMapping("/profile")\n'
        '  @PreAuthorize("isAuthenticated()")\n'
        '  public String profile() { return "ok"; }\n'
        '}\n',
    )
    assert len(routes) == 1
    assert routes[0]["authentication"] == "present"


def test_spring_request_mapping_with_explicit_method(tmp_path: Path) -> None:
    routes = _routes(tmp_path,
        '@Controller\n'
        'class LegacyController {\n'
        '  @RequestMapping("/legacy", method = RequestMethod.POST)\n'
        '  public String legacy() { return "ok"; }\n'
        '}\n',
    )
    assert len(routes) == 1
    assert routes[0]["method"] == ["POST"]


def test_spring_dynamic_class_prefix_is_omitted(tmp_path: Path) -> None:
    routes = _routes(tmp_path,
        '@RestController\n'
        '@RequestMapping(ROOT_PATH)\n'
        'public class UserController {\n'
        '  @GetMapping("/users")\n'
        '  public String users() { return "ok"; }\n'
        '}\n',
    )
    assert routes == []


def test_spring_comments_and_strings_not_mapped(tmp_path: Path) -> None:
    routes = _routes(tmp_path,
        '@RestController\n'
        'public class UserController {\n'
        '  // @GetMapping("/ghost")\n'
        '  /* @PostMapping("/ghost2") */\n'
        '  String text = "@DeleteMapping(\\"/ghost3\\")";\n'
        '}\n',
    )
    assert routes == []


def test_spring_non_controller_method_is_not_mapped(tmp_path: Path) -> None:
    routes = _routes(tmp_path,
        'class RandomClass {\n'
        '  @GetMapping("/internal")\n'
        '  public String inner() { return "ok"; }\n'
        '}\n',
    )
    assert routes == []


def test_spring_literal_path_required(tmp_path: Path) -> None:
    routes = _routes(tmp_path,
        '@RestController\n'
        'public class UserController {\n'
        '  @GetMapping(dynamicPath)\n'
        '  public String users() { return "ok"; }\n'
        '}\n',
    )
    assert routes == []


def test_method_mapping_in_following_noncontroller_is_not_attributed(tmp_path: Path) -> None:
    routes = _routes(tmp_path,
        '@RestController\n'
        'class ValidController {\n'
        '  @GetMapping("/real")\n'
        '  public String real() { return "ok"; }\n'
        '}\n'
        'class UnrelatedClass {\n'
        '  @GetMapping("/not-a-controller")\n'
        '  public String fake() { return "wrong"; }\n'
        '}\n',
    )
    assert len(routes) == 1
    assert routes[0]["path"] == "/real"
