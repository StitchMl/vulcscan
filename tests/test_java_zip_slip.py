from __future__ import annotations

from pathlib import Path

from vulcscan.models import Confidence
from vulcscan.scanner import scan_path


def _findings(root: Path, text: str):
    (root / "Extractor.java").write_text(text, encoding="utf-8")
    return [f for f in scan_path(root, cve=False).findings if f.rule_id == "JAVA-ZIPSLIP-001"]


def test_java_zip_entry_name_written_without_containment(tmp_path: Path) -> None:
    found = _findings(tmp_path,
        "class Extractor {\n"
        "  void run(ZipInputStream zip, File root) {\n"
        "    ZipEntry entry = zip.getNextEntry();\n"
        "    File output = new File(root, entry.getName());\n"
        "    FileOutputStream stream = new FileOutputStream(output);\n"
        "  }\n"
        "}\n",
    )
    assert len(found) == 1
    assert found[0].cwe == "CWE-22"
    assert found[0].confidence == Confidence.MEDIUM
    assert found[0].source is not None
    assert found[0].source.line == 4
    assert found[0].location.line == 5
    assert found[0].test_vectors
    assert [step.kind for step in found[0].flow] == ["SOURCE", "SINK"]
    assert not any(r.machine_applicable for r in found[0].remediations)


def test_java_zip_entry_files_copy_to_path(tmp_path: Path) -> None:
    found = _findings(tmp_path,
        "class Extractor {\n"
        "  void run(ZipInputStream zip, File root, InputStream input) {\n"
        "    ZipEntry entry = zip.getNextEntry();\n"
        "    File output = new File(root, entry.getName());\n"
        "    Files.copy(input, output.toPath());\n"
        "  }\n"
        "}\n",
    )
    assert len(found) == 1


def test_canonical_containment_check_abstains(tmp_path: Path) -> None:
    found = _findings(tmp_path,
        "class Extractor {\n"
        "  void run(ZipInputStream zip, File root) {\n"
        "    ZipEntry entry = zip.getNextEntry();\n"
        "    File output = new File(root, entry.getName());\n"
        "    String canonical = output.getCanonicalPath();\n"
        "    if (!canonical.startsWith(root.getCanonicalPath())) throw new SecurityException();\n"
        "    new FileOutputStream(output);\n"
        "  }\n"
        "}\n",
    )
    assert not found


def test_no_write_sink_not_reported(tmp_path: Path) -> None:
    found = _findings(tmp_path,
        "class Extractor {\n"
        "  void inspect(ZipInputStream zip, File root) {\n"
        "    ZipEntry entry = zip.getNextEntry();\n"
        "    File output = new File(root, entry.getName());\n"
        "    System.out.println(output);\n"
        "  }\n"
        "}\n",
    )
    assert not found


def test_unrelated_filename_source_not_reported(tmp_path: Path) -> None:
    found = _findings(tmp_path,
        "class Extractor {\n"
        "  void run(File root, User user) {\n"
        "    File output = new File(root, user.getName());\n"
        "    new FileOutputStream(output);\n"
        "  }\n"
        "}\n",
    )
    assert not found


def test_comments_and_strings_cannot_create_finding(tmp_path: Path) -> None:
    found = _findings(tmp_path,
        "class Extractor {\n"
        "  void run() {\n"
        "    // ZipEntry entry = zip.getNextEntry();\n"
        "    // File output = new File(root, entry.getName());\n"
        "    // new FileOutputStream(output);\n"
        '    String text = "new FileOutputStream(output)";\n'
        "  }\n"
        "}\n",
    )
    assert not found


def test_wrong_write_target_not_reported(tmp_path: Path) -> None:
    found = _findings(tmp_path,
        "class Extractor {\n"
        "  void run(ZipInputStream zip, File root) {\n"
        "    ZipEntry entry = zip.getNextEntry();\n"
        "    File output = new File(root, entry.getName());\n"
        "    new FileOutputStream(trusted);\n"
        "  }\n"
        "}\n",
    )
    assert not found
