from __future__ import annotations

from pathlib import Path

from vulcscan.scanner import scan_path


def _found(root: Path, text: str):
    (root / "unzip.go").write_text(text, encoding="utf-8")
    return [f for f in scan_path(root, cve=False).findings if f.rule_id == "GO-ZIPSLIP-001"]


def test_zip_entry_name_joined_and_written_without_guard(tmp_path: Path) -> None:
    findings = _found(tmp_path,
        'package main\n'
        'import ("archive/zip"; "path/filepath"; "os")\n'
        'func extract(reader *zip.ReadCloser, root string) {\n'
        '  for _, item := range reader.File {\n'
        '    dest := filepath.Join(root, item.Name)\n'
        '    out, err := os.Create(dest)\n'
        '    _ = out\n'
        '    _ = err\n'
        '  }\n'
        '}\n',
    )
    assert len(findings) == 1
    assert findings[0].source is not None
    assert findings[0].source.line == 5
    assert findings[0].location.line == 6
    assert findings[0].cwe == "CWE-22"
    assert findings[0].test_vectors
    assert not any(rem.machine_applicable for rem in findings[0].remediations)


def test_go_openfile_direct_zip_entry_path(tmp_path: Path) -> None:
    assert len(_found(tmp_path,
        'package main\n'
        'import "archive/zip"\n'
        'func extract(reader *zip.ReadCloser, root string) {\n'
        ' for _, entry := range reader.File {\n'
        '  output := filepath.Join(root, entry.Name)\n'
        '  f, e := os.OpenFile(output, 2, 0600)\n'
        '  _, _ = f, e\n'
        ' }\n'
        '}\n',
    )) == 1


def test_relative_containment_guard_suppresses(tmp_path: Path) -> None:
    assert not _found(tmp_path,
        'package main\n'
        'import ("archive/zip"; "path/filepath"; "strings")\n'
        'func extract(reader *zip.ReadCloser, root string) {\n'
        ' for _, entry := range reader.File {\n'
        '  output := filepath.Join(root, entry.Name)\n'
        '  rel, err := filepath.Rel(root, output)\n'
        '  if err != nil || strings.HasPrefix(rel, "..") { continue }\n'
        '  _, _ = os.Create(output)\n'
        ' }\n'
        '}\n',
    )


def test_unrelated_file_name_does_not_count_as_archive_member(tmp_path: Path) -> None:
    assert not _found(tmp_path,
        'package main\n'
        'import "archive/zip"\n'
        'func f(root string) {\n'
        ' path := filepath.Join(root, user.Name)\n'
        ' _, _ = os.Create(path)\n'
        '}\n',
    )


def test_no_file_write_does_not_trigger(tmp_path: Path) -> None:
    assert not _found(tmp_path,
        'package main\n'
        'import "archive/zip"\n'
        'func f(reader *zip.ReadCloser, root string) {\n'
        ' for _, entry := range reader.File {\n'
        '  path := filepath.Join(root, entry.Name)\n'
        '  println(path)\n'
        ' }\n'
        '}\n',
    )


def test_missing_zip_import_does_not_trigger(tmp_path: Path) -> None:
    assert not _found(tmp_path,
        'package main\n'
        'func f(reader any, root string) {\n'
        ' for _, entry := range reader.File {\n'
        '  path := filepath.Join(root, entry.Name)\n'
        '  _, _ = os.Create(path)\n'
        ' }\n'
        '}\n',
    )


def test_comment_and_string_decoys_ignored(tmp_path: Path) -> None:
    assert not _found(tmp_path,
        'package main\n'
        'import "archive/zip"\n'
        'func f() {\n'
        ' // for _, entry := range reader.File {\n'
        ' //  path := filepath.Join(root, entry.Name)\n'
        ' //  os.Create(path)\n'
        ' // }\n'
        ' text := "os.Create(path)"\n'
        ' _ = text\n'
        '}\n',
    )
