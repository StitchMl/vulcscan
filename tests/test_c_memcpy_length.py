from __future__ import annotations

from pathlib import Path

from vulcscan.scanner import scan_path


def _issues(root: Path, code: str, name: str = "copy.c"):
    (root / name).write_text(code, encoding="utf-8")
    return [
        f for f in scan_path(root, cve=False).findings
        if f.rule_id == "C-BUFFER-001" and "memcpy" in f.sink
    ]


def test_memcpy_count_from_argv_into_fixed_buffer(tmp_path: Path) -> None:
    findings = _issues(
        tmp_path,
        "void process(char **argv, const char *src) {\n"
        " char dest[64];\n"
        " size_t count = strtoul(argv[1], 0, 10);\n"
        " memcpy(dest, src, count);\n"
        "}\n",
    )
    assert len(findings) == 1
    assert findings[0].location.line == 4
    assert findings[0].cwe == "CWE-120"
    assert findings[0].test_vectors
    assert not any(rem.machine_applicable for rem in findings[0].remediations)


def test_cpp_uint8_array_and_atoi(tmp_path: Path) -> None:
    assert len(_issues(
        tmp_path,
        "void process(char **argv, char *src) {\n"
        " uint8_t payload[16];\n"
        " int size = atoi(argv[2]);\n"
        " memcpy(payload, src, size);\n"
        "}\n", "copy.cpp",
    )) == 1


def test_guarded_copy_not_flagged(tmp_path: Path) -> None:
    assert not _issues(
        tmp_path,
        "void process(char **argv, char *src) {\n"
        " char dest[32];\n"
        " size_t n = strtoul(argv[1], 0, 10);\n"
        " if (n > sizeof(dest)) return;\n"
        " memcpy(dest, src, n);\n"
        "}\n",
    )


def test_clamped_copy_not_flagged(tmp_path: Path) -> None:
    assert not _issues(
        tmp_path,
        "void process(char **argv, char *src) {\n"
        " char dest[32];\n"
        " size_t n = strtoul(argv[1], 0, 10);\n"
        " n = std::min(n, sizeof(dest));\n"
        " memcpy(dest, src, n);\n"
        "}\n", "copy.cpp",
    )


def test_fixed_known_length_not_flagged(tmp_path: Path) -> None:
    assert not _issues(
        tmp_path,
        "void process(char *src) {\n"
        " char dest[32];\n"
        " memcpy(dest, src, sizeof(dest));\n"
        "}\n",
    )


def test_overwritten_length_not_flagged(tmp_path: Path) -> None:
    assert not _issues(
        tmp_path,
        "void process(char **argv, char *src) {\n"
        " char dest[32];\n"
        " int n = atoi(argv[1]);\n"
        " n = 8;\n"
        " memcpy(dest, src, n);\n"
        "}\n",
    )


def test_comments_and_strings_are_not_calls(tmp_path: Path) -> None:
    assert not _issues(
        tmp_path,
        "void process(char **argv) {\n"
        " char dest[32];\n"
        " int n = atoi(argv[1]);\n"
        ' const char *s = "memcpy(dest, src, n)";\n'
        " // memcpy(dest, src, n);\n"
        "}\n",
    )


def test_no_fixed_array_no_report(tmp_path: Path) -> None:
    assert not _issues(
        tmp_path,
        "void process(char **argv, char *dest, char *src) {\n"
        " int n = atoi(argv[1]);\n"
        " memcpy(dest, src, n);\n"
        "}\n",
    )
