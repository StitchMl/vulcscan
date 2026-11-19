from __future__ import annotations

from pathlib import Path

from vulcscan.scanner import scan_path


def _scan(tmp_path: Path, source: str):
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    return scan_path(tmp_path, cve=False).findings


def _args(findings):
    return [finding for finding in findings if finding.rule_id == "PY-ARG-001"]


def test_fixed_git_executable_with_request_argument(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "import subprocess\n"
        "from flask import request\n"
        "ref = request.args['ref']\n"
        "subprocess.run(['git', 'checkout', ref], check=True)\n",
    )
    matches = _args(findings)
    assert len(matches) == 1
    assert matches[0].cwe == "CWE-88"
    assert matches[0].source is not None
    assert matches[0].source.line == 3
    assert matches[0].location.line == 4
    assert matches[0].flow[0].kind == "SOURCE"
    assert matches[0].flow[-1].kind == "SINK"
    assert not any(rem.machine_applicable for rem in matches[0].remediations)
    assert matches[0].test_vectors


def test_import_alias_and_direct_request_field(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "import subprocess as sp\n"
        "from flask import request\n"
        "sp.check_output(['tar', request.form['name']])\n",
    )
    assert len(_args(findings)) == 1


def test_asyncio_exec_args_are_checked(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "import asyncio\n"
        "from flask import request\n"
        "async def run():\n"
        "    await asyncio.create_subprocess_exec('curl', request.args.get('url'))\n",
    )
    assert len(_args(findings)) == 1


def test_option_terminator_and_numeric_cast_are_not_flagged(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "import subprocess\n"
        "from flask import request\n"
        "v = request.args['name']\n"
        "subprocess.run(['git', '--', v])\n"
        "subprocess.run(['git', int(request.args['count'])])\n",
    )
    assert not _args(findings)


def test_local_args_and_fixed_values_not_flagged(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "import subprocess\n"
        "import sys\n"
        "subprocess.run(['git', sys.argv[1]])\n"
        "subprocess.run(['git', 'status'])\n",
    )
    assert not _args(findings)


def test_reassignment_clears_remote_taint(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "import subprocess\n"
        "from flask import request\n"
        "value = request.args['cmd']\n"
        "value = 'status'\n"
        "subprocess.run(['git', value])\n",
    )
    assert not _args(findings)


def test_dynamic_program_and_shell_true_are_out_of_scope(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "import subprocess\n"
        "from flask import request\n"
        "command = request.args['command']\n"
        "subprocess.run([command, 'status'])\n"
        "subprocess.run(['git', command], shell=True)\n",
    )
    assert not _args(findings)


def test_source_variable_does_not_leak_across_functions(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "import subprocess\n"
        "from flask import request\n"
        "def one():\n"
        "    value = request.args['cmd']\n"
        "def two():\n"
        "    subprocess.run(['git', value])\n",
    )
    assert not _args(findings)


def test_invalid_python_is_not_executed(tmp_path: Path) -> None:
    findings = _scan(tmp_path, "import subprocess\nif (\n")
    assert not _args(findings)
