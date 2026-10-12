from vulcscan.guidance import enrich_finding
from vulcscan.models import Confidence, Finding, FlowStep, Location, Severity


def _finding(
    rule_id: str,
    language: str,
    sink: str,
    evidence: str,
    source_code: str,
) -> Finding:
    location = Location("service.test", 8)
    finding = Finding(
        rule_id=rule_id,
        name="test",
        cwe="CWE-20",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category="test",
        language=language,
        location=location,
        sink=sink,
        evidence=evidence,
        reason="traced remote input",
        source=Location("service.test", 4),
        flow=[
            FlowStep("SOURCE", Location("service.test", 4), source_code, "remote source"),
            FlowStep("SINK", location, evidence, "unsafe sink"),
        ],
    )
    enrich_finding(finding)
    return finding


def _vector(finding: Finding) -> str:
    return finding.test_vectors[0]


def test_command_vector_uses_traced_variable_and_unix_shell_syntax() -> None:
    finding = _finding(
        "JS-CMD-001",
        "JavaScript",
        "child_process.exec",
        "exec('ping ' + host)",
        "const host = req.query.host;",
    )

    vector = _vector(finding)
    assert "`host`" in vector
    assert "; printf 'VULCSCAN_CMD_%s\\n'" in vector
    assert "service.test:8" in vector


def test_command_vector_selects_windows_cmd_delimiters() -> None:
    finding = _finding(
        "CS-CMD-001",
        "C#",
        "Process.Start",
        'Process.Start("cmd.exe", "/c ping " + host)',
        'string host = Request.Query["host"];',
    )

    vector = _vector(finding)
    assert "& echo VULCSCAN_CMD_%RANDOM% & rem" in vector
    assert "process log" in vector


def test_xss_vector_selects_attribute_breakout_from_sink_context() -> None:
    finding = _finding(
        "JS-XSS-001",
        "JavaScript",
        "res.send",
        'res.send(`<a href="${next}">continue</a>`)',
        "const next = req.query.next;",
    )

    vector = _vector(finding)
    assert "`next`" in vector
    assert "autofocus onfocus=console.log('VULCSCAN_XSS')" in vector
    assert "HTML attribute context" in vector


def test_xss_vector_selects_script_string_breakout() -> None:
    finding = _finding(
        "PHP-XSS-001",
        "PHP",
        "echo",
        "echo \"<script>const name='$name';</script>\";",
        "$name = $_GET['name'];",
    )

    assert "';console.log('VULCSCAN_XSS');//" in _vector(finding)


def test_path_vector_selects_target_operating_system_separator() -> None:
    windows = _finding(
        "CS-PATH-001",
        "C#",
        "File.ReadAllText",
        "File.ReadAllText(Path.Combine(basePath, name))",
        'string name = Request.Query["name"];',
    )
    unix = _finding(
        "PY-PATH-001",
        "Python",
        "open",
        "open(base / name)",
        "name = request.args['name']",
    )

    assert r"..\vulcscan-canary.txt" in _vector(windows)
    assert "../vulcscan-canary.txt" in _vector(unix)


def test_ssrf_vector_accounts_for_relative_url_resolution() -> None:
    finding = _finding(
        "JS-SSRF-001",
        "JavaScript",
        "fetch",
        "fetch(new URL(target, baseUrl))",
        "const target = req.query.target;",
    )

    vector = _vector(finding)
    assert "//127.0.0.1:18080/VULCSCAN_SSRF" in vector
    assert "http://[::1]:18080/VULCSCAN_SSRF" in vector


def test_deserialization_vector_selects_pickle_canary() -> None:
    finding = _finding(
        "PY-DESER-001",
        "Python",
        "pickle.loads",
        "pickle.loads(blob)",
        "blob = request.get_data()",
    )

    vector = _vector(finding)
    assert "`blob`" in vector
    assert "`builtins.print`" in vector
    assert "VULCSCAN_DESER" in vector


def test_code_vector_uses_language_expression_and_observation_channel() -> None:
    finding = _finding(
        "PY-CODE-001",
        "Python",
        "eval",
        "eval(expression)",
        "expression = request.args['expression']",
    )

    vector = _vector(finding)
    assert "__import__('builtins').print('VULCSCAN_CODE')" in vector
    assert "stdout and logs" in vector


def test_upload_vector_matches_php_execution_context() -> None:
    finding = _finding(
        "UPLOAD-MIME-001",
        "PHP",
        "move_uploaded_file",
        "move_uploaded_file($_FILES['file']['tmp_name'], 'uploads/' . $name);",
        "$name = $_FILES['file']['name'];",
    )

    vector = _vector(finding)
    assert "vulcscan-probe.php.jpg" in vector
    assert "<?php /* VULCSCAN_UPLOAD */ ?>" in vector
    assert "image/jpeg" in vector


def test_redirect_vector_handles_origin_relative_checks() -> None:
    finding = _finding(
        "OPEN-REDIRECT-001",
        "JavaScript",
        "res.redirect",
        "res.redirect(new URL(next, requestUrl))",
        "const next = req.query.next;",
    )

    vector = _vector(finding)
    assert "//vulcscan-redirect.example/VULCSCAN_REDIRECT" in vector
    assert "without following redirects" in vector
    assert "`next`" in vector
