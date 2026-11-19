"""Regression checks for SonarCloud's native automatic-analysis configuration."""
from __future__ import annotations

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _properties() -> dict[str, str]:
    lines = (ROOT / ".sonarcloud.properties").read_text(encoding="utf-8").splitlines()
    return dict(line.split("=", 1) for line in lines if line.strip() and not line.lstrip().startswith("#"))


def test_automatic_analysis_keeps_production_and_test_scopes_separate() -> None:
    properties = _properties()
    assert properties["sonar.projectKey"] == "StitchMl_vulcscan"
    assert properties["sonar.sources"] == "vulcscan"
    assert properties["sonar.tests"] == "tests"
    assert not (set(properties["sonar.sources"].split(",")) & set(properties["sonar.tests"].split(",")))
    assert not any(key in properties for key in ("sonar.coverage.exclusions", "sonar.issue.ignore.multicriteria"))


def test_automatic_analysis_version_tracks_release_and_supported_python() -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text("utf-8"))
    properties = _properties()
    assert properties["sonar.projectVersion"] == pyproject["project"]["version"]
    assert properties["sonar.python.version"] == "3.11,3.12"
