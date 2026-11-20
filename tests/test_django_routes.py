from __future__ import annotations

from pathlib import Path

from vulcscan.scanner import scan_path


def _routes(root: Path, urls: str, views: str | None = None):
    (root / "urls.py").write_text(urls, encoding="utf-8")
    if views is not None:
        (root / "views.py").write_text(views, encoding="utf-8")
    return scan_path(root, cve=False, attack_surface=True).metadata["attack_surface"]


def test_django_literal_urlpatterns_and_local_view_module(tmp_path: Path) -> None:
    items = _routes(
        tmp_path,
        "from django.urls import path\n"
        "from . import views\n"
        "urlpatterns = [\n"
        "    path('users/<int:id>/', views.user_detail, name='user-detail'),\n"
        "    path('health/', views.health),\n"
        "]\n",
        "def user_detail(request, id):\n"
        "    return id\n"
        "def health(request):\n"
        "    return 'ok'\n",
    )
    assert [(x["path"], x["method"]) for x in items] == [
        ("/users/<int:id>/", ["ANY"]), ("/health/", ["ANY"])
    ]
    assert items[0]["handler"] == "user_detail"
    assert items[0]["handler_file"] == "views.py"
    assert items[0]["line"] == 4


def test_alias_view_and_login_required_wrapper(tmp_path: Path) -> None:
    items = _routes(
        tmp_path,
        "from django.urls import path as url\n"
        "from .views import get_account as account\n"
        "urlpatterns = [url('accounts/', login_required(account))]\n",
        "def get_account(request):\n"
        "    return 'ok'\n",
    )
    assert len(items) == 1
    assert items[0]["handler"] == "get_account"
    assert items[0]["authentication"] == "present"
    assert items[0]["handler_file"] == "views.py"


def test_class_based_view_as_view(tmp_path: Path) -> None:
    items = _routes(
        tmp_path,
        "from django.urls import path\n"
        "from . import views\n"
        "urlpatterns = [path('profile/', views.ProfileView.as_view())]\n",
        "class ProfileView:\n"
        "    def get(self, request):\n"
        "        return 'ok'\n",
    )
    assert len(items) == 1
    assert items[0]["handler"] == "ProfileView"


def test_dynamic_paths_and_includes_are_not_inferred(tmp_path: Path) -> None:
    items = _routes(
        tmp_path,
        "from django.urls import path, include\n"
        "from . import views\n"
        "urlpatterns = [\n"
        " path(prefix, views.handler),\n"
        " path('api/', include('api.urls')),\n"
        " path('safe/', views.handler),\n"
        "]\n",
        "def handler(request):\n"
        "    pass\n",
    )
    assert [item["path"] for item in items] == ["/safe/"]


def test_non_django_path_function_is_not_route(tmp_path: Path) -> None:
    assert _routes(tmp_path,
        "def path(*args):\n"
        "    pass\n"
        "urlpatterns = [path('fake/', handler)]\n",
    ) == []


def test_missing_imported_view_module_never_claims_known_handler(tmp_path: Path) -> None:
    items = _routes(tmp_path,
        "from django.urls import path\n"
        "from . import views\n"
        "urlpatterns = [path('users/', views.detail)]\n",
    )
    assert len(items) == 1
    assert items[0]["handler"] is None


def test_invalid_python_source_is_ignored(tmp_path: Path) -> None:
    assert _routes(tmp_path, "urlpatterns = [path('oops', \n") == []


def test_django_login_required_wrapper_preserves_remote_taint(tmp_path: Path) -> None:
    _routes(
        tmp_path,
        "from django.urls import path\n"
        "from django.contrib.auth.decorators import login_required\n"
        "from . import views\n"
        "urlpatterns = [path('run/<str:command>/', login_required(views.run))]\n",
        "import subprocess\n"
        "def run(request, command):\n"
        "    subprocess.run(command, shell=True)\n",
    )
    result = scan_path(tmp_path, cve=False)
    remote = [
        finding for finding in result.findings
        if finding.rule_id == "PY-CMD-001" and finding.source is not None
    ]
    assert len(remote) == 1
    assert remote[0].source.file == "views.py"
    assert remote[0].location.file == "views.py"


def test_django_nested_known_wrappers_preserve_remote_taint(tmp_path: Path) -> None:
    _routes(
        tmp_path,
        "from django.urls import path\n"
        "from django.contrib.auth.decorators import login_required\n"
        "from django.contrib.admin.views.decorators import staff_member_required\n"
        "from . import views\n"
        "urlpatterns = [path('run/<command>/', staff_member_required(login_required(views.run)))]\n",
        "import subprocess\n"
        "def run(request, command):\n"
        "    subprocess.run(command, shell=True)\n",
    )
    result = scan_path(tmp_path, cve=False)
    assert len([
        finding for finding in result.findings
        if finding.rule_id == "PY-CMD-001" and finding.source is not None
    ]) == 1


def test_django_unknown_url_wrapper_does_not_infer_request_flow(tmp_path: Path) -> None:
    _routes(
        tmp_path,
        "from django.urls import path\n"
        "from . import views\n"
        "urlpatterns = [path('run/<command>/', custom_wrapper(views.run))]\n",
        "import subprocess\n"
        "def run(request, command):\n"
        "    subprocess.run(command, shell=True)\n",
    )
    result = scan_path(tmp_path, cve=False)
    assert not [
        finding for finding in result.findings
        if finding.rule_id == "PY-CMD-001" and finding.source is not None
    ]
