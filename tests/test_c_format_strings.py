from __future__ import annotations

from pathlib import Path

from vulcscan.scanner import scan_path


def _scan(tmp_path: Path, filename: str, source: str):
    (tmp_path / filename).write_text(source, encoding="utf-8")
    return scan_path(tmp_path, cve=False).findings


def _formats(findings):
    return [item for item in findings if item.rule_id == "C-FORMAT-001"]


def test_direct_argv_printf_is_flagged(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path, "main.c",
        "#include <stdio.h>\n"
        "int main(int argc, char **argv) {\n"
        "  printf(argv[1]);\n"
        "}\n",
    )
    matches = _formats(findings)
    assert len(matches) == 1
    assert matches[0].location.line == 3
    assert matches[0].cwe == "CWE-134"
    assert matches[0].test_vectors
    assert matches[0].remediations
    assert not any(item.machine_applicable for item in matches[0].remediations)


def test_fgets_to_fprintf_is_flagged(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path, "main.cpp",
        "#include <stdio.h>\n"
        "int main() {\n"
        "  char buffer[128];\n"
        "  fgets(buffer, sizeof(buffer), stdin);\n"
        "  fprintf(stderr, buffer);\n"
        "}\n",
    )
    assert len(_formats(findings)) == 1


def test_recv_to_syslog_is_flagged(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path, "main.c",
        "void handle(int sock) {\n"
        "  char data[256];\n"
        "  recv(sock, data, sizeof(data), 0);\n"
        "  syslog(LOG_INFO, data);\n"
        "}\n",
    )
    assert len(_formats(findings)) == 1


def test_literal_format_with_untrusted_value_is_not_flagged(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path, "safe.c",
        "void show(int argc, char **argv) {\n"
        "  printf(\"%s\", argv[1]);\n"
        "  fprintf(stderr, \"%s\", argv[1]);\n"
        "}\n",
    )
    assert not _formats(findings)


def test_trusted_variable_format_is_not_flagged(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path, "safe.c",
        "const char *fixed_format = \"hello\";\n"
        "void show() { printf(fixed_format); }\n",
    )
    assert not _formats(findings)


def test_comments_and_strings_cannot_trigger_format_rule(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path, "safe.c",
        "void show() {\n"
        "  // printf(argv[1]);\n"
        "  char *text = \"printf(argv[1])\";\n"
        "  printf(\"%s\", text);\n"
        "}\n",
    )
    assert not _formats(findings)


def test_close_by_input_in_unrelated_file_does_not_trigger(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path, "safe.cpp",
        "void show() { printf(buffer); }\n",
    )
    assert not _formats(findings)
