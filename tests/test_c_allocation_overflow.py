from __future__ import annotations

from pathlib import Path

from vulcscan.scanner import scan_path


def _issues(root: Path, content: str, name: str = "allocator.c"):
    (root / name).write_text(content, encoding="utf-8")
    return [f for f in scan_path(root, cve=False).findings if f.rule_id == "C-ALLOC-001"]


def test_atoi_argv_count_multiplied_in_malloc(tmp_path: Path) -> None:
    found = _issues(tmp_path,
        "#include <stdlib.h>\n"
        "void run(char **argv) {\n"
        "    int count = atoi(argv[1]);\n"
        "    char *p = malloc(count * sizeof(int));\n"
        "}\n")
    assert len(found) == 1
    assert found[0].location.line == 4
    assert found[0].cwe == "CWE-190"
    assert found[0].test_vectors
    assert all(not r.machine_applicable for r in found[0].remediations)


def test_reverse_sizeof_product_in_cpp(tmp_path: Path) -> None:
    found = _issues(tmp_path,
        "void run(char **argv) {\n"
        "  size_t items = strtoul(argv[2], nullptr, 10);\n"
        "  auto buffer = malloc(sizeof(char) * items);\n"
        "}\n", "allocator.cpp")
    assert len(found) == 1


def test_checked_multiplication_not_reported(tmp_path: Path) -> None:
    found = _issues(tmp_path,
        "void run(char **argv) {\n"
        "  size_t count = strtoul(argv[1], 0, 10);\n"
        "  if (count > SIZE_MAX / sizeof(int)) return;\n"
        "  void *p = malloc(count * sizeof(int));\n"
        "}\n")
    assert found == []


def test_constant_count_and_calloc_not_reported(tmp_path: Path) -> None:
    found = _issues(tmp_path,
        "void run() {\n"
        "  size_t count = 10;\n"
        "  malloc(count * sizeof(int));\n"
        "  calloc(count, sizeof(int));\n"
        "}\n")
    assert found == []


def test_overwrite_clears_cli_provenance(tmp_path: Path) -> None:
    found = _issues(tmp_path,
        "void run(char **argv) {\n"
        "  int count = atoi(argv[1]);\n"
        "  count = 4;\n"
        "  malloc(count * sizeof(int));\n"
        "}\n")
    assert found == []


def test_comment_and_string_are_not_sources(tmp_path: Path) -> None:
    found = _issues(tmp_path,
        "void run() {\n"
        "  // count = atoi(argv[1]);\n"
        '  const char *s = "count = atoi(argv[1]);";\n'
        "  malloc(count * sizeof(int));\n"
        "}\n")
    assert found == []
