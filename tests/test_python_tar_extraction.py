from __future__ import annotations

from pathlib import Path

from vulcscan.scanner import scan_path


def _scan(tmp_path: Path, text: str):
    (tmp_path / "upload.py").write_text(text, encoding="utf-8")
    return scan_path(tmp_path, cve=False).findings


def _tar_findings(findings):
    return [finding for finding in findings if finding.rule_id == "PY-TAR-EXTRACT-001"]


def test_uploaded_tar_extracted_without_filter(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "import tarfile\n"
        "from flask import request\n"
        "def upload():\n"
        "    file = request.files['archive']\n"
        "    with tarfile.open(fileobj=file.stream) as archive:\n"
        "        archive.extractall('/srv/data')\n",
    )
    matches = _tar_findings(findings)
    assert len(matches) == 1
    assert matches[0].source is not None
    assert matches[0].source.line == 4
    assert matches[0].location.line == 6
    assert matches[0].cwe == "CWE-22"
    assert matches[0].test_vectors
    assert not any(r.machine_applicable for r in matches[0].remediations)


def test_uploaded_tar_assigned_then_extracted(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "import tarfile as tf\n"
        "from flask import request\n"
        "def upload():\n"
        "    archive = tf.open(fileobj=request.files['archive'].stream)\n"
        "    archive.extractall(path='/tmp/destination')\n",
    )
    assert len(_tar_findings(findings)) == 1


def test_explicit_data_filter_does_not_flag(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "import tarfile\n"
        "from flask import request\n"
        "def upload():\n"
        "    with tarfile.open(fileobj=request.files['archive'].stream) as archive:\n"
        "        archive.extractall('/tmp', filter='data')\n",
    )
    assert not _tar_findings(findings)


def test_custom_filter_is_not_guessed_unsafe(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "import tarfile\n"
        "from flask import request\n"
        "def upload(filter_archive):\n"
        "    with tarfile.open(fileobj=request.files['archive'].stream) as archive:\n"
        "        archive.extractall('/tmp', filter=filter_archive)\n",
    )
    assert not _tar_findings(findings)


def test_trusted_local_tar_not_flagged(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "import tarfile\n"
        "with tarfile.open('/srv/trusted/release.tar') as archive:\n"
        "    archive.extractall('/srv/release')\n",
    )
    assert not _tar_findings(findings)


def test_zipfile_extractall_is_not_assumed_vulnerable(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "import zipfile\n"
        "from flask import request\n"
        "def upload():\n"
        "    with zipfile.ZipFile(request.files['archive'].stream) as archive:\n"
        "        archive.extractall('/tmp')\n",
    )
    assert not _tar_findings(findings)


def test_tar_handler_scope_does_not_leak(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "import tarfile\n"
        "from flask import request\n"
        "def upload():\n"
        "    archive = tarfile.open(fileobj=request.files['archive'].stream)\n"
        "def other():\n"
        "    archive.extractall('/tmp')\n",
    )
    assert not _tar_findings(findings)


def test_explicit_archive_extraction_filter_property(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "import tarfile\n"
        "from flask import request\n"
        "def upload():\n"
        "    archive = tarfile.open(fileobj=request.files['archive'].stream)\n"
        "    archive.extraction_filter = tarfile.data_filter\n"
        "    archive.extractall('/tmp')\n",
    )
    assert not _tar_findings(findings)
