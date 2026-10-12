from __future__ import annotations

import struct
from pathlib import Path

from vulcscan.scanner import scan_path


def _pe(*, mitigations: bool) -> bytes:
    data = bytearray(512)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", data, 0x98, 0x10B)
    struct.pack_into("<H", data, 0x98 + 70, 0x0140 if mitigations else 0)
    data[300:306] = b"strcpy"
    return bytes(data)


def test_pe_binary_is_scanned_without_execution(tmp_path: Path) -> None:
    (tmp_path / "service.exe").write_bytes(_pe(mitigations=False))
    result = scan_path(tmp_path, offline=True, cve=False)
    ids = {finding.rule_id for finding in result.findings}
    assert "BINARY-DANGEROUS-001" in ids
    assert "BINARY-HARDENING-001" in ids
    assert result.metadata["files_analyzed"] == 1
    assert "PE binary" in result.metadata["languages"]


def test_hardened_pe_has_no_hardening_finding(tmp_path: Path) -> None:
    (tmp_path / "safe.dll").write_bytes(_pe(mitigations=True))
    result = scan_path(tmp_path, offline=True, cve=False)
    assert "BINARY-HARDENING-001" not in {finding.rule_id for finding in result.findings}
