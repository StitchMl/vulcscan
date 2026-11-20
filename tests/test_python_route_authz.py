from __future__ import annotations

from pathlib import Path

from vulcscan.scanner import scan_path


def _authz(root: Path, source: str, **options):
    (root / "views.py").write_text(source, encoding="utf-8")
    return [f for f in scan_path(root, cve=False, **options).findings if f.rule_id == "AUTHZ-SCOPE-001"]


def test_flask_path_identifier_direct_orm_lookup(tmp_path: Path) -> None:
    found = _authz(tmp_path,
        "@app.route('/users/<int:user_id>')\n"
        "def details(user_id):\n"
        "    user = User.query.get(user_id)\n"
        "    return user.email\n",
    )
    assert len(found) == 1
    assert found[0].source is not None
    assert found[0].source.line == 1
    assert found[0].location.line == 3
    assert found[0].cwe == "CWE-639"
    assert [step.kind for step in found[0].flow] == ["SOURCE", "SINK"]
    assert found[0].test_vectors
    assert all(not r.machine_applicable for r in found[0].remediations)


def test_fastapi_router_get_and_session_lookup(tmp_path: Path) -> None:
    found = _authz(tmp_path,
        "@router.get('/accounts/{account_id}')\n"
        "async def account(account_id, db):\n"
        "    return db.session.get(Account, account_id)\n",
        remote_only=True,
    )
    assert len(found) == 1


def test_multiple_decorators_preserve_route_line(tmp_path: Path) -> None:
    found = _authz(tmp_path,
        "@login_required\n"
        "@bp.get('/files/<uuid:file_id>')\n"
        "def file(file_id):\n"
        "    return File.query.get_or_404(file_id)\n",
    )
    assert len(found) == 1
    assert found[0].source.line == 2


def test_owner_scope_in_filter_prevents_alert(tmp_path: Path) -> None:
    found = _authz(tmp_path,
        "@app.get('/users/<int:user_id>')\n"
        "def details(user_id):\n"
        "    return User.query.filter_by(id=user_id, owner_id=current_user.id).first()\n",
    )
    assert not found


def test_explicit_owner_check_prevents_alert(tmp_path: Path) -> None:
    found = _authz(tmp_path,
        "@app.get('/docs/<int:doc_id>')\n"
        "def detail(doc_id):\n"
        "    doc = Doc.query.get(doc_id)\n"
        "    if doc.owner_id != current_user.id:\n"
        "        abort(403)\n"
        "    return doc\n",
    )
    assert not found


def test_non_identifier_and_non_route_lookups_not_flagged(tmp_path: Path) -> None:
    found = _authz(tmp_path,
        "@app.get('/search/{term}')\n"
        "def search(term):\n"
        "    return Doc.query.get(term)\n"
        "def internal(user_id):\n"
        "    return User.query.get(user_id)\n",
    )
    assert not found


def test_parameter_not_used_in_database_query(tmp_path: Path) -> None:
    found = _authz(tmp_path,
        "@app.get('/users/{user_id}')\n"
        "def user(user_id):\n"
        "    return User.query.get(123)\n",
    )
    assert not found


def test_invalid_python_never_executes(tmp_path: Path) -> None:
    assert not _authz(tmp_path, "@app.get('/users/{user_id}')\ndef user(:\n")


def test_django_view_primary_key_lookup(tmp_path: Path) -> None:
    found = _authz(tmp_path,
        "from django.shortcuts import get_object_or_404\n"
        "def document(request, document_id):\n"
        "    return get_object_or_404(Document, pk=document_id)\n",
        remote_only=True,
    )
    assert len(found) == 1
    assert found[0].source is not None
    assert found[0].source.line == 2
    assert found[0].location.line == 3


def test_django_class_view_objects_get(tmp_path: Path) -> None:
    found = _authz(tmp_path,
        "class DocumentView:\n"
        "    def get(self, request, pk):\n"
        "        return Document.objects.get(pk=pk)\n",
    )
    assert len(found) == 1


def test_django_owner_check_prevents_alert(tmp_path: Path) -> None:
    found = _authz(tmp_path,
        "from django.shortcuts import get_object_or_404\n"
        "def document(request, document_id):\n"
        "    document = get_object_or_404(Document, pk=document_id)\n"
        "    if document.owner_id != request.user.id:\n"
        "        raise PermissionDenied\n"
        "    return document\n",
    )
    assert not found


def test_non_view_helper_is_not_treated_as_django_endpoint(tmp_path: Path) -> None:
    found = _authz(tmp_path,
        "def load_document(document_id):\n"
        "    return Document.objects.get(pk=document_id)\n",
    )
    assert not found
