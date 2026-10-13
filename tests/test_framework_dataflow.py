from __future__ import annotations

from pathlib import Path

import pytest

from vulcscan.models import ScanConfig
from vulcscan.scanner import scan


@pytest.mark.parametrize(
    ("filename", "source", "rule_id"),
    [
        (
            "search.php",
            """<?php
$term = $request->getQueryParams()['q'];
$em->createNativeQuery("SELECT * FROM documents WHERE title = '" . $term . "'");
""",
            "PHP-SQL-001",
        ),
        (
            "Search.java",
            """public List<Row> search(@QueryParam("q") String q) {
    return entityManager.createNativeQuery("SELECT * FROM documents WHERE title='" + q + "'").getResultList();
}
""",
            "JAVA-SQL-001",
        ),
        (
            "handler.go",
            """func search(c *gin.Context, db *gorm.DB) {
    order := c.Query("order")
    db.Order(order).Find(&rows)
}
""",
            "GO-SQL-001",
        ),
        (
            "handler.go",
            """func search(ctx echo.Context, db *gorm.DB) {
    filter := ctx.QueryParam("filter")
    db.Where(filter).Find(&rows)
}
""",
            "GO-SQL-001",
        ),
    ],
)
def test_framework_sources_reach_raw_sql(
    tmp_path: Path, filename: str, source: str, rule_id: str
) -> None:
    (tmp_path / filename).write_text(source, encoding="utf-8")

    report = scan(ScanConfig(tmp_path, offline=True, cve=False))

    matches = [finding for finding in report.findings if finding.rule_id == rule_id]
    assert matches
    assert matches[0].source is not None
    assert matches[0].test_vectors
    assert matches[0].remediations


def test_gorm_bound_condition_is_not_reported(tmp_path: Path) -> None:
    (tmp_path / "handler.go").write_text(
        """func search(c *gin.Context, db *gorm.DB) {
    name := c.Query("name")
    db.Where("name = ?", name).Find(&rows)
}
""",
        encoding="utf-8",
    )

    report = scan(ScanConfig(tmp_path, offline=True, cve=False))

    assert not [finding for finding in report.findings if finding.rule_id == "GO-SQL-001"]


def test_django_url_parameter_flows_across_files(tmp_path: Path) -> None:
    (tmp_path / "views.py").write_text(
        """from django.db import connection

def document(request, title):
    with connection.cursor() as cursor:
        cursor.execute("SELECT body FROM documents WHERE title='" + title + "'")
""",
        encoding="utf-8",
    )
    (tmp_path / "urls.py").write_text(
        """from django.urls import path
from views import document

urlpatterns = [path("documents/<path:title>/", document)]
""",
        encoding="utf-8",
    )

    report = scan(ScanConfig(tmp_path, offline=True, cve=False))

    finding = next(item for item in report.findings if item.rule_id == "PY-SQL-001")
    assert finding.source is not None
    assert finding.source.file == "views.py"
    assert "Django URL parameter" in finding.flow[0].description


def test_django_typed_url_parameter_is_treated_as_safe(tmp_path: Path) -> None:
    (tmp_path / "views.py").write_text(
        """from django.db import connection

def document(request, document_id):
    connection.cursor().execute("SELECT body FROM documents WHERE id=" + str(document_id))
""",
        encoding="utf-8",
    )
    (tmp_path / "urls.py").write_text(
        """from django.urls import path
from views import document

urlpatterns = [path("documents/<int:document_id>/", document)]
""",
        encoding="utf-8",
    )

    report = scan(ScanConfig(tmp_path, offline=True, cve=False))

    assert not [finding for finding in report.findings if finding.rule_id == "PY-SQL-001"]


@pytest.mark.parametrize(
    ("filename", "source", "rule_id"),
    [
        (
            "State.php",
            """<?php
$state = $request->getParsedBody()['state'];
$object = unserialize($state);
""",
            "PHP-DESER-001",
        ),
        (
            "Proxy.java",
            """public byte[] proxy(ServerRequest request) {
    String target = request.queryParam("url").orElseThrow();
    return restTemplate.getForObject(target, byte[].class);
}
""",
            "JAVA-SSRF-001",
        ),
        (
            "download.go",
            """func download(ctx *fiber.Ctx) {
    name := ctx.Query("file")
    data, _ := os.ReadFile(name)
    ctx.Send(data)
}
""",
            "GO-PATH-001",
        ),
    ],
)
def test_framework_sources_cover_other_high_impact_sinks(
    tmp_path: Path, filename: str, source: str, rule_id: str
) -> None:
    (tmp_path / filename).write_text(source, encoding="utf-8")

    report = scan(ScanConfig(tmp_path, offline=True, cve=False))

    finding = next(item for item in report.findings if item.rule_id == rule_id)
    assert finding.source is not None
    assert finding.test_vectors
    assert finding.remediations
