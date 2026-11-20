from __future__ import annotations

from pathlib import Path

from vulcscan.models import Confidence
from vulcscan.scanner import scan_path


def _write(root: Path, path: str, contents: str) -> None:
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(contents, encoding="utf-8")


def _cmd_findings(root: Path, *, sourced: bool = False):
    return [
        finding for finding in scan_path(root, cve=False).findings
        if finding.rule_id == "JS-CMD-001" and (not sourced or finding.source is not None)
    ]


def test_esm_direct_wrapper_receives_remote_query_across_files(tmp_path: Path) -> None:
    _write(tmp_path, "routes.js",
        "import { unsafe as launch } from './service.js';\n"
        "function handler(req, res) {\n"
        "  const command = req.query.cmd;\n"
        "  launch(command);\n"
        "}\n")
    _write(tmp_path, "service.js",
        "const cp = require('child_process');\n"
        "export function unsafe(value) { cp.exec(value); }\n")
    findings = _cmd_findings(tmp_path, sourced=True)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.location.file == "routes.js"
    assert finding.source is not None
    assert finding.source.file == "routes.js"
    assert finding.confidence == Confidence.MEDIUM
    assert any(loc.file == "service.js" for loc in finding.related_locations)
    assert any(step.location.file == "service.js" and step.kind == "SINK" for step in finding.flow)


def test_commonjs_direct_wrapper_receives_remote_input(tmp_path: Path) -> None:
    _write(tmp_path, "handler.js",
        "const { unsafe: runCommand } = require('./service');\n"
        "function handler(req, res) { runCommand(req.body.command); }\n")
    _write(tmp_path, "service.js",
        "const { exec } = require('child_process');\n"
        "function unsafe(value) { exec(value); }\n"
        "module.exports = { unsafe };\n")
    findings = _cmd_findings(tmp_path, sourced=True)
    assert findings
    assert findings[0].location.file == "handler.js"


def test_constant_input_and_numeric_validation_are_not_reported(tmp_path: Path) -> None:
    _write(tmp_path, "routes.ts",
        "import { unsafe } from './service';\n"
        "function handler(req) {\n"
        "  unsafe('uptime');\n"
        "  unsafe(Number(req.query.count));\n"
        "}\n")
    _write(tmp_path, "service.ts",
        "import { exec } from 'node:child_process';\n"
        "export function unsafe(value) { exec(value); }\n")
    assert not _cmd_findings(tmp_path, sourced=True)


def test_guarded_or_transformed_wrappers_are_not_summarized(tmp_path: Path) -> None:
    _write(tmp_path, "routes.js",
        "import { safe } from './service.js';\n"
        "function handler(req) { safe(req.query.cmd); }\n")
    _write(tmp_path, "service.js",
        "const cp = require('child_process');\n"
        "export function safe(value) {\n"
        "  const clean = parseInt(value, 10);\n"
        "  cp.exec(clean);\n"
        "}\n")
    assert not _cmd_findings(tmp_path, sourced=True)


def test_ambiguous_module_specifier_is_not_guessed(tmp_path: Path) -> None:
    _write(tmp_path, "routes.js",
        "import { unsafe } from './service';\n"
        "function handler(req) { unsafe(req.query.cmd); }\n")
    _write(tmp_path, "service.ts",
        "const cp = require('child_process');\n"
        "export function unsafe(value) { cp.exec(value); }\n")
    _write(tmp_path, "service.js",
        "const cp = require('child_process');\n"
        "export function unsafe(value) { cp.exec(value); }\n")
    assert not _cmd_findings(tmp_path, sourced=True)


def test_non_local_import_does_not_gain_sink_summary(tmp_path: Path) -> None:
    _write(tmp_path, "routes.js",
        "import { unsafe } from 'remote-library';\n"
        "function handler(req) { unsafe(req.query.cmd); }\n")
    assert not _cmd_findings(tmp_path, sourced=True)


def test_ordinary_local_script_findings_remain_intact(tmp_path: Path) -> None:
    _write(tmp_path, "routes.js",
        "const cp = require('child_process');\n"
        "function handler(req) { cp.exec(req.query.cmd); }\n")
    findings = _cmd_findings(tmp_path)
    assert findings
    assert findings[0].location.file == "routes.js"


def test_shadowed_imported_symbol_does_not_create_cross_file_taint(tmp_path: Path) -> None:
    _write(tmp_path, "routes.js",
        "import { unsafe } from './service.js';\n"
        "function handler(unsafe, req) { unsafe(req.query.cmd); }\n")
    _write(tmp_path, "service.js",
        "const cp = require('child_process');\n"
        "export function unsafe(value) { cp.exec(value); }\n")
    assert not _cmd_findings(tmp_path, sourced=True)


def test_one_hop_imported_filesystem_sink_uses_remote_source(tmp_path: Path) -> None:
    _write(tmp_path, "routes.js",
        "import { openFile } from './service.js';\n"
        "function handler(req) { openFile(req.query.name); }\n")
    _write(tmp_path, "service.js",
        "const fs = require('fs');\n"
        "export function openFile(file) { fs.readFileSync(file); }\n")
    report = scan_path(tmp_path, cve=False)
    found = [
        finding for finding in report.findings
        if finding.rule_id == "JS-PATH-001" and finding.source is not None
    ]
    assert found
    assert found[0].location.file == "routes.js"
    assert any(loc.file == "service.js" for loc in found[0].related_locations)


def test_one_hop_imported_fetch_sink_uses_remote_source(tmp_path: Path) -> None:
    _write(tmp_path, "routes.js",
        "import { openUrl } from './service.js';\n"
        "function handler(req) { openUrl(req.query.target); }\n")
    _write(tmp_path, "service.js",
        "export function openUrl(url) { fetch(url); }\n")
    report = scan_path(tmp_path, cve=False)
    found = [
        finding for finding in report.findings
        if finding.rule_id == "JS-SSRF-001" and finding.source is not None
    ]
    assert found
    assert found[0].location.file == "routes.js"


def test_two_hop_relay_preserves_remote_source_and_original_sink(tmp_path: Path) -> None:
    _write(tmp_path, "routes.js",
        "import { forward } from './controller.js';\n"
        "function handler(req) { forward(req.query.cmd); }\n")
    _write(tmp_path, "controller.js",
        "import { unsafe } from './service.js';\n"
        "export function forward(value) { unsafe(value); }\n")
    _write(tmp_path, "service.js",
        "const cp = require('child_process');\n"
        "export function unsafe(value) { cp.exec(value); }\n")

    findings = _cmd_findings(tmp_path, sourced=True)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.location.file == "routes.js"
    assert finding.source is not None
    assert finding.source.file == "routes.js"
    assert any(loc.file == "service.js" for loc in finding.related_locations)


def test_two_hop_relay_rejects_transforms_and_longer_chains(tmp_path: Path) -> None:
    _write(tmp_path, "routes.js",
        "import { forward } from './controller.js';\n"
        "function handler(req) { forward(req.query.cmd); }\n")
    _write(tmp_path, "controller.js",
        "import { unsafe } from './service.js';\n"
        "export function forward(value) { unsafe(String(value)); }\n")
    _write(tmp_path, "service.js",
        "const cp = require('child_process');\n"
        "export function unsafe(value) { cp.exec(value); }\n")
    assert not _cmd_findings(tmp_path, sourced=True)


def test_two_hop_relay_does_not_resolve_ambiguous_module(tmp_path: Path) -> None:
    _write(tmp_path, "routes.js",
        "import { forward } from './controller';\n"
        "function handler(req) { forward(req.query.cmd); }\n")
    _write(tmp_path, "controller.js",
        "import { unsafe } from './service.js';\n"
        "export function forward(value) { unsafe(value); }\n")
    _write(tmp_path, "controller.ts",
        "import { unsafe } from './service.js';\n"
        "export function forward(value) { unsafe(value); }\n")
    _write(tmp_path, "service.js",
        "const cp = require('child_process');\n"
        "export function unsafe(value) { cp.exec(value); }\n")
    assert not _cmd_findings(tmp_path, sourced=True)


def test_imported_sink_does_not_treat_shadowed_fetch_parameter_as_ssrf(tmp_path: Path) -> None:
    _write(tmp_path, "routes.js",
        "import { unsafe } from './service.js';\n"
        "function handler(req) { unsafe(req.query.target); }\n")
    _write(tmp_path, "service.js",
        "export function unsafe(fetch) { fetch(fetch); }\n")
    findings = [
        finding for finding in scan_path(tmp_path, cve=False).findings
        if finding.rule_id == "JS-SSRF-001" and finding.source is not None
    ]
    assert not findings


def test_imported_sink_does_not_treat_shadowed_exec_parameter_as_command_sink(tmp_path: Path) -> None:
    _write(tmp_path, "routes.js",
        "import { unsafe } from './service.js';\n"
        "function handler(req) { unsafe(req.query.command); }\n")
    _write(tmp_path, "service.js",
        "const { exec } = require('child_process');\n"
        "export function unsafe(exec) { exec(exec); }\n")
    assert not _cmd_findings(tmp_path, sourced=True)


def test_actual_fetch_sink_still_traces_request_across_two_hops(tmp_path: Path) -> None:
    _write(tmp_path, "routes.js",
        "import { forward } from './controller.js';\n"
        "function handler(req) { forward(req.query.target); }\n")
    _write(tmp_path, "controller.js",
        "import { openUrl } from './service.js';\n"
        "export function forward(value) { openUrl(value); }\n")
    _write(tmp_path, "service.js",
        "export function openUrl(value) { fetch(value); }\n")
    findings = [
        finding for finding in scan_path(tmp_path, cve=False).findings
        if finding.rule_id == "JS-SSRF-001" and finding.source is not None
    ]
    assert len(findings) == 1
    assert findings[0].location.file == "routes.js"
    assert any(loc.file == "service.js" for loc in findings[0].related_locations)


def test_four_hop_import_chain_traces_original_sink(tmp_path: Path) -> None:
    _write(tmp_path, "route.js",
        "import { first } from './first.js';\n"
        "function handler(req) { first(req.query.cmd); }\n")
    _write(tmp_path, "first.js",
        "import { second } from './second.js';\n"
        "export function first(value) { second(value); }\n")
    _write(tmp_path, "second.js",
        "import { third } from './third.js';\n"
        "export function second(value) { third(value); }\n")
    _write(tmp_path, "third.js",
        "import { unsafe } from './sink.js';\n"
        "export function third(value) { unsafe(value); }\n")
    _write(tmp_path, "sink.js",
        "const cp = require('child_process');\n"
        "export function unsafe(value) { cp.exec(value); }\n")
    findings = _cmd_findings(tmp_path, sourced=True)

    assert len(findings) == 1
    assert findings[0].location.file == "route.js"
    assert findings[0].source is not None
    assert findings[0].source.file == "route.js"
    assert any(location.file == "sink.js" for location in findings[0].related_locations)


def test_import_chain_beyond_four_hops_is_not_guessed(tmp_path: Path) -> None:
    _write(tmp_path, "route.js",
        "import { entry } from './entry.js';\n"
        "function handler(req) { entry(req.query.cmd); }\n")
    _write(tmp_path, "entry.js",
        "import { first } from './first.js';\n"
        "export function entry(value) { first(value); }\n")
    _write(tmp_path, "first.js",
        "import { second } from './second.js';\n"
        "export function first(value) { second(value); }\n")
    _write(tmp_path, "second.js",
        "import { third } from './third.js';\n"
        "export function second(value) { third(value); }\n")
    _write(tmp_path, "third.js",
        "import { unsafe } from './sink.js';\n"
        "export function third(value) { unsafe(value); }\n")
    _write(tmp_path, "sink.js",
        "const cp = require('child_process');\n"
        "export function unsafe(value) { cp.exec(value); }\n")
    assert not _cmd_findings(tmp_path, sourced=True)


def test_relay_tracks_second_argument_into_first_wrapper_parameter(tmp_path: Path) -> None:
    _write(tmp_path, "routes.js",
        "import { forward } from './controller.js';\n"
        "function handler(req) { forward(req.query.cmd, 'label'); }\n")
    _write(tmp_path, "controller.js",
        "import { unsafe } from './service.js';\n"
        "export function forward(command, label) { unsafe(label, command); }\n")
    _write(tmp_path, "service.js",
        "const cp = require('child_process');\n"
        "export function unsafe(label, command) { cp.exec(command); }\n")
    findings = _cmd_findings(tmp_path, sourced=True)
    assert len(findings) == 1
    assert findings[0].location.file == "routes.js"
    assert any(loc.file == "service.js" for loc in findings[0].related_locations)


def test_relay_ignores_safe_argument_in_another_position(tmp_path: Path) -> None:
    _write(tmp_path, "routes.js",
        "import { forward } from './controller.js';\n"
        "function handler(req) { forward(req.query.cmd, 'constant'); }\n")
    _write(tmp_path, "controller.js",
        "import { unsafe } from './service.js';\n"
        "export function forward(command, label) { unsafe(command, label); }\n")
    _write(tmp_path, "service.js",
        "const cp = require('child_process');\n"
        "export function unsafe(label, command) { cp.exec(command); }\n")
    assert not _cmd_findings(tmp_path, sourced=True)


def test_relay_rejects_transformed_argument_even_with_second_sink_parameter(tmp_path: Path) -> None:
    _write(tmp_path, "routes.js",
        "import { forward } from './controller.js';\n"
        "function handler(req) { forward(req.query.cmd); }\n")
    _write(tmp_path, "controller.js",
        "import { unsafe } from './service.js';\n"
        "export function forward(command) { unsafe('tag', String(command)); }\n")
    _write(tmp_path, "service.js",
        "const cp = require('child_process');\n"
        "export function unsafe(label, command) { cp.exec(command); }\n")
    assert not _cmd_findings(tmp_path, sourced=True)


