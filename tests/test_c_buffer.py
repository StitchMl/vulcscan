from __future__ import annotations

from pathlib import Path

from vulcscan.scanner import scan_path


def _scan(root: Path, source: str, extension: str = ".c"):
    (root / ("source" + extension)).write_text(source, encoding="utf-8")
    return [f for f in scan_path(root, cve=False).findings if f.rule_id == "C-BUFFER-001"]


def test_unbounded_gets_is_flagged(tmp_path: Path) -> None:
    found = _scan(tmp_path,
        "#include <stdio.h>\n"
        "void read_name() {\n"
        " char name[64];\n"
        " gets(name);\n"
        "}\n"
    )
    assert len(found) == 1
    assert found[0].cwe == "CWE-120"
    assert found[0].location.line == 4
    assert found[0].test_vectors
    assert not any(fix.machine_applicable for fix in found[0].remediations)


def test_unbounded_scanf_string_is_flagged(tmp_path: Path) -> None:
    found = _scan(tmp_path,
        "void read_input() { char buf[16]; scanf(\"%s\", buf); }\n",
        ".cpp",
    )
    assert len(found) == 1


def test_argv_strcpy_is_flagged(tmp_path: Path) -> None:
    found = _scan(tmp_path,
        "void mainf(char **argv) { char dst[20]; strcpy(dst, argv[1]); }\n",
    )
    assert len(found) == 1


def test_argv_sprintf_is_flagged(tmp_path: Path) -> None:
    found = _scan(tmp_path,
        "void mainf(char **argv) { char dst[20]; sprintf(dst, \"%s\", argv[1]); }\n",
    )
    assert len(found) == 1


def test_bounded_scanf_and_fgets_are_not_flagged(tmp_path: Path) -> None:
    found = _scan(tmp_path,
        "void safe() {\n"
        "  char buf[32];\n"
        "  scanf(\"%31s\", buf);\n"
        "  fgets(buf, sizeof(buf), stdin);\n"
        "}\n"
    )
    assert not found


def test_strcpy_of_fixed_literal_is_not_flagged(tmp_path: Path) -> None:
    found = _scan(tmp_path, 'void safe() { char buf[32]; strcpy(buf, "safe"); }\n')
    assert not found


def test_comments_and_strings_are_not_treated_as_calls(tmp_path: Path) -> None:
    found = _scan(tmp_path,
        "void safe() {\n"
        "  // gets(buffer);\n"
        '  const char *text = "gets(buffer)";\n'
        "  /* strcpy(buffer, argv[1]); */\n"
        '  puts("scanf(\\"%s\\", buffer)");\n'
        "}\n"
    )
    assert not found
