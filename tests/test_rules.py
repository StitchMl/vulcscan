from __future__ import annotations

from pathlib import Path

import pytest

from vulcscan.models import Confidence, Severity
from vulcscan.javascript import analyze_javascript
from vulcscan.lexical import lexical_findings
from vulcscan.python_analysis import analyze_python
from vulcscan.rules import RULES, remediations_for
from vulcscan.structured import analyze_structured


FIXTURES = Path(__file__).parent / "fixtures"


def _findings(text: str, language: str, name: str):
    if language == "Python":
        return analyze_python(name, text)[0]
    return lexical_findings(name, name, language, text)


def _rule_ids(text: str, *, language: str = "Python", name: str = "app.py") -> list[str]:
    return [finding.rule_id for finding in _findings(text, language, name)]


def test_rule_catalog_has_complete_stable_metadata() -> None:
    assert len(RULES) == len(set(RULES))
    assert {"PY-CMD-001", "JS-CMD-001", "PY-SQL-001", "JS-SQL-001"} <= RULES.keys()
    assert {"CWE-22", "CWE-78", "CWE-89", "CWE-94", "CWE-502", "CWE-918"} <= {
        item.cwe for item in RULES.values()
    }
    for rule_id, definition in RULES.items():
        assert definition.rule_id == rule_id
        assert definition.name
        assert definition.cwe.startswith("CWE-")
        assert isinstance(definition.severity, Severity)
        assert isinstance(definition.default_confidence, Confidence)
        assert definition.category
        assert definition.explanation.endswith(".")


def test_hardcoded_secret_is_redacted() -> None:
    value = "prod_live_1234567890abcdef"
    findings = _findings(f'api_key = "{value}"\n', "Python", "settings.py")

    assert [finding.rule_id for finding in findings] == ["SECRET-001"]
    assert value not in findings[0].evidence
    assert "<redacted>" in findings[0].evidence


@pytest.mark.parametrize(
    "text, language",
    [
        ('# password = "a-real-looking-secret"\n', "Python"),
        ('// password = "a-real-looking-secret";\n', "JavaScript"),
        ('password = "placeholder"\n', "Python"),
        ('password = os.environ["PASSWORD"]\n', "Python"),
        ('const password = process.env.PASSWORD;\n', "JavaScript"),
    ],
)
def test_secret_rule_ignores_comments_placeholders_and_environment_reads(
    text: str,
    language: str,
) -> None:
    suffix = ".py" if language == "Python" else ".js"
    assert "SECRET-001" not in _rule_ids(text, language=language, name=f"app{suffix}")


@pytest.mark.parametrize(
    "text, language, expected",
    [
        ("requests.get(url, verify=False)\n", "Python", True),
        ("requests.get(url, verify=True)\n", "Python", False),
        ('const options = { rejectUnauthorized: false };\n', "JavaScript", True),
        ('const options = { rejectUnauthorized: true };\n', "JavaScript", False),
        ("tls.Config{InsecureSkipVerify: true}\n", "Go", True),
    ],
)
def test_tls_rule_requires_an_explicit_unsafe_switch(
    text: str,
    language: str,
    expected: bool,
) -> None:
    detected = "TLS-VERIFY-001" in _rule_ids(text, language=language)
    assert detected is expected


def test_weak_hash_requires_password_context() -> None:
    assert "WEAK-HASH-001" in _rule_ids("digest = hashlib.sha1(password.encode()).hexdigest()\n")
    assert "WEAK-HASH-001" not in _rule_ids("digest = hashlib.sha1(content).hexdigest()\n")


def test_weak_random_requires_security_sensitive_assignment() -> None:
    assert "WEAK-RANDOM-001" in _rule_ids("reset_code = random.randint(100000, 999999)\n")
    assert "WEAK-RANDOM-001" not in _rule_ids("dice_roll = random.randint(1, 6)\n")


def test_credentialed_wildcard_cors_requires_both_settings() -> None:
    # Starlette reflects the request origin when credentials are allowed with "*".
    unsafe = 'app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)\n'
    origin_only = 'app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=False)\n'
    express_unsafe = "app.use(cors({ origin: true, credentials: true }));\n"
    express_safe = "app.use(cors({ origin: true }));\n"

    assert "CORS-001" in _rule_ids(unsafe)
    assert "CORS-001" not in _rule_ids(origin_only)
    assert "CORS-001" in _rule_ids(express_unsafe, language="JavaScript", name="app.js")
    assert "CORS-001" not in _rule_ids(express_safe, language="JavaScript", name="app.js")


def test_docker_rule_checks_only_the_final_stage() -> None:
    safe = "FROM python:3.12 AS build\nUSER root\nFROM python:3.12-slim\nUSER 10001\n"
    unsafe = "FROM python:3.12-slim\nRUN python -m compileall /app\n"

    assert "DOCKER-ROOT-001" not in _rule_ids(safe, language="Dockerfile", name="Dockerfile")
    assert "DOCKER-ROOT-001" in _rule_ids(unsafe, language="Dockerfile", name="Dockerfile")


def test_every_rule_has_deterministic_remediation_metadata() -> None:
    for rule_id in RULES:
        remediations = remediations_for(rule_id, "unsafe_call(value)")
        assert remediations
        assert remediations[0].preferred is True
        assert isinstance(remediations[0].patch_confidence, Confidence)
        assert remediations[0].patch_risk in {"LOW", "MEDIUM", "HIGH"}
        assert remediations[0].guidance


def test_every_rule_has_a_safe_verification_vector() -> None:
    from vulcscan.rules import test_vectors_for

    assert not [rule_id for rule_id in RULES if not test_vectors_for(rule_id)]


def test_generic_rules_return_the_same_order() -> None:
    source = 'debug = True\napi_key = "prod_live_1234567890abcdef"\n'
    first = _findings(source, "Python", "app.py")
    second = _findings(source, "Python", "app.py")

    assert [item.as_dict() for item in first] == [item.as_dict() for item in second]


def test_python_fixture_tracks_sources_to_precise_sinks() -> None:
    source = (FIXTURES / "vulnerable" / "python" / "app.py").read_text(encoding="utf-8")
    findings, parser_error = analyze_python("app.py", source)
    by_rule = {item.rule_id: item for item in findings}

    assert parser_error is None
    expected_lines = {
        "PY-CMD-001": (17, 18),
        "PY-SQL-001": (24, 26),
        "PY-CODE-001": (31, 32),
        "PY-PATH-001": (37, 38),
        "PY-SSRF-001": (43, 44),
        "PY-DESER-001": (49, 49),
    }
    assert expected_lines.keys() <= by_rule.keys()
    for rule_id, (source_line, sink_line) in expected_lines.items():
        finding = by_rule[rule_id]
        assert finding.confidence is Confidence.HIGH
        assert finding.source is not None
        assert finding.source.line == source_line
        assert finding.location.line == sink_line
        assert finding.patch_location == finding.location
        assert finding.flow[0].kind == "SOURCE"
        assert finding.flow[-1].kind == "SINK"


def test_javascript_fixture_tracks_sources_to_precise_sinks() -> None:
    source = (FIXTURES / "vulnerable" / "javascript" / "app.js").read_text(
        encoding="utf-8"
    )
    findings = analyze_javascript("app.js", source, "JavaScript")
    by_rule = {item.rule_id: item for item in findings}

    expected_lines = {
        "JS-CMD-001": (10, 11),
        "JS-SQL-001": (15, 16),
        "JS-CODE-001": (20, 21),
        "JS-PATH-001": (25, 26),
        "JS-SSRF-001": (30, 30),
    }
    assert expected_lines.keys() <= by_rule.keys()
    for rule_id, (source_line, sink_line) in expected_lines.items():
        finding = by_rule[rule_id]
        assert finding.confidence is Confidence.HIGH
        assert finding.source is not None
        assert finding.source.line == source_line
        assert finding.location.line == sink_line


def test_python_allowlist_stops_taint_for_command_execution() -> None:
    source = '''
from flask import request
import subprocess

command = request.args["command"]
if command not in {"status", "log"}:
    raise ValueError("unsupported command")
subprocess.run(command, shell=True)
'''
    findings, parser_error = analyze_python("app.py", source)

    assert parser_error is None
    assert all(item.rule_id != "PY-CMD-001" for item in findings)


def test_python_parameterized_sql_is_not_reported() -> None:
    source = '''
from flask import request

username = request.args["username"]
cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
'''
    findings, parser_error = analyze_python("app.py", source)

    assert parser_error is None
    assert all(item.rule_id != "PY-SQL-001" for item in findings)


def test_python_sqlalchemy_expression_is_not_raw_sql() -> None:
    source = '''
from flask import request

username = request.json.get("username")
user = db.session.execute(db.select(User).filter_by(username=username)).scalar_one_or_none()
'''
    findings, parser_error = analyze_python("app.py", source)

    assert parser_error is None
    assert all(item.rule_id != "PY-SQL-001" for item in findings)


def test_bound_sql_with_internal_dynamic_identifier_is_not_assumed_remote() -> None:
    safe_unknown = '''
def read(table_name, key):
    return db.execute(f"SELECT value FROM {table_name} WHERE key = ?", (key,))
'''
    remote_identifier = '''
from flask import request
table_name = request.args["table"]
db.execute(f"SELECT value FROM {table_name} WHERE key = ?", (1,))
'''

    safe_findings, _ = analyze_python("store.py", safe_unknown)
    unsafe_findings, _ = analyze_python("store.py", remote_identifier)

    assert all(item.rule_id != "PY-SQL-001" for item in safe_findings)
    assert any(item.rule_id == "PY-SQL-001" for item in unsafe_findings)


def test_python_json_response_is_not_html_output() -> None:
    source = '''
from flask import request, Response
import json

value = request.args["value"]
return Response(json.dumps({"value": value}), headers={"Content-Type": "application/json"})
'''
    findings, parser_error = analyze_python("app.py", source)

    assert parser_error is None
    assert all(item.rule_id != "PY-XSS-001" for item in findings)


def test_javascript_binary_response_is_not_html_output() -> None:
    source = '''
app.get("/file/:id", async (req, res) => {
  const file = await Files.findOne({ where: { id: req.params.id } });
  res.setHeader("Content-Type", "application/octet-stream");
  res.send(file.content);
});
'''
    findings = analyze_javascript("app.js", source, "JavaScript")

    assert all(item.rule_id != "JS-XSS-001" for item in findings)


def test_runtime_json_records_do_not_flood_secret_findings() -> None:
    findings = lexical_findings(
        "info.json",
        "backend/data/0123456789abcdef/info.json",
        "JSON",
        '{"password": "disposable-user-password", "name": "test"}\n',
    )

    assert all(item.rule_id != "SECRET-001" for item in findings)


@pytest.mark.parametrize(
    ("language", "source"),
    [
        ("Python", 'with open(password_path, "w") as f:\n    f.write(password)\n'),
        (
            "JavaScript",
            "await pool.query('INSERT INTO owners (username, password) VALUES ($1, $2)', [username, password]);\n",
        ),
    ],
)
def test_cleartext_password_persistence_is_reported(language: str, source: str) -> None:
    ids = {
        item.rule_id
        for item in lexical_findings("account" + (".py" if language == "Python" else ".js"), "src/account", language, source)
    }

    assert "CLEARTEXT-PASSWORD-001" in ids


def test_malleable_encryption_without_integrity_is_reported() -> None:
    unsafe = "cipher = AES.new(server_key, AES.MODE_CBC, iv=iv)\ntoken = cipher.encrypt(data)\n"
    safe = "cipher = AES.new(server_key, AES.MODE_GCM, nonce=nonce)\nciphertext, tag = cipher.encrypt_and_digest(data)\n"

    assert "UNAUTH-ENCRYPTION-001" in {
        item.rule_id for item in lexical_findings("token.py", "src/token.py", "Python", unsafe)
    }
    assert "UNAUTH-ENCRYPTION-001" not in {
        item.rule_id for item in lexical_findings("token.py", "src/token.py", "Python", safe)
    }


def test_cbc_with_signature_is_not_reported_as_unauthenticated() -> None:
    signed = (
        "cipher = AES.new(server_key, AES.MODE_CBC, iv=iv)\n"
        "ciphertext = cipher.encrypt(data)\n"
        "signature = sign(ciphertext, signing_key)\n"
    )

    assert "UNAUTH-ENCRYPTION-001" not in {
        item.rule_id for item in lexical_findings("token.py", "src/token.py", "Python", signed)
    }


def test_dynamic_svg_text_is_reported_but_encoded_text_is_not() -> None:
    unsafe = "const svg = `<svg><text>${item.text}</text></svg>`; return new Response(svg, {headers: {'Content-Type': 'image/svg+xml'}});"
    safe = "const svg = `<svg><text>${escapeXml(item.text)}</text></svg>`; return new Response(svg, {headers: {'Content-Type': 'image/svg+xml'}});"

    assert "JS-XSS-001" in _rule_ids(unsafe, language="TypeScript", name="svg.ts")
    assert "JS-XSS-001" not in _rule_ids(safe, language="TypeScript", name="svg.ts")


def test_go_cel_compilation_of_variable_expression_is_reported() -> None:
    source = "env, _ := cel.NewEnv()\nast, _ := env.Compile(document.Expression)\n"

    assert "GO-CODE-001" in _rule_ids(source, language="Go", name="evaluator.go")


def test_libxml_replace_entities_is_reported() -> None:
    source = "const document = libxmljs.parseXml(svg, { replaceEntities: true });\n"

    assert "XXE-001" in _rule_ids(source, language="TypeScript", name="parser.ts")


def test_sequelize_literal_with_remote_value_is_raw_sql() -> None:
    source = '''
app.post("/upload", async (req, res) => {
  const content = req.body.content;
  await Files.create({ content: sequelize.literal(`decode('${content}', 'base64')`) });
});
'''
    findings = analyze_javascript("upload.js", source, "JavaScript")

    assert any(item.rule_id == "JS-SQL-001" for item in findings)


def test_route_resource_lookup_requires_principal_scope() -> None:
    unsafe = '''
router.get('/file/:id', async (req, res) => {
  const id = req.params.id;
  const file = await Files.findOne({ where: { id } });
  res.json(file);
});
'''
    safe = '''
router.get('/file/:id', async (req, res) => {
  const id = req.params.id;
  const file = await Files.findOne({ where: { id, owner_id: req.user.id } });
  res.json(file);
});
'''

    assert "AUTHZ-SCOPE-001" in _rule_ids(unsafe, language="JavaScript", name="files.js")
    assert "AUTHZ-SCOPE-001" not in _rule_ids(safe, language="JavaScript", name="files.js")


def test_python_interprocedural_argument_flow_reaches_sink() -> None:
    source = '''
from flask import request
import subprocess

def run_backup(name):
    subprocess.run("backup " + name, shell=True)

def handler():
    run_backup(request.args["name"])
'''
    findings, parser_error = analyze_python("app.py", source)
    precise = [
        item
        for item in findings
        if item.rule_id == "PY-CMD-001" and item.source is not None
    ]

    assert parser_error is None
    assert len(precise) == 1
    assert precise[0].source.line == 9
    assert precise[0].location.line == 6
    assert any(step.kind == "PROPAGATION" for step in precise[0].flow)


def test_python_parser_failure_isolated() -> None:
    findings, parser_error = analyze_python("broken.py", "def broken(\n")

    assert findings == []
    assert parser_error is not None
    assert parser_error.startswith("SyntaxError:")


@pytest.mark.parametrize(
    "language, source, rule_id",
    [
        ("PHP", "$command = $_GET['command'];\nsystem($command);\n", "PHP-CMD-001"),
        (
            "Java",
            'String command = request.getParameter("command");\nRuntime.getRuntime().exec(command);\n',
            "JAVA-CMD-001",
        ),
        (
            "C#",
            'var path = Request.Query["path"];\nFile.ReadAllText(path);\n',
            "CS-PATH-001",
        ),
        (
            "Go",
            'url := r.URL.Query().Get("url")\nhttp.Get(url)\n',
            "GO-SSRF-001",
        ),
        ("Ruby", "command = params[:command]\nsystem(command)\n", "RB-CMD-001"),
        ("C", "char* command = argv[1];\nsystem(command);\n", "C-CMD-001"),
        ("C++", "auto command = argv[1];\nsystem(command);\n", "C-CMD-001"),
        ("Shell", "command=$1\nsh -c $command\n", "SH-CMD-001"),
        (
            "PowerShell",
            "$command = $args[0]\nInvoke-Expression $command\n",
            "PS-CODE-001",
        ),
        ("Batch", "set command=%1\ncall %command%\n", "BAT-CMD-001"),
    ],
)
def test_structured_language_rules_track_simple_source_to_sink_flow(
    language: str,
    source: str,
    rule_id: str,
) -> None:
    findings = analyze_structured("app.txt", source, language)
    finding = next(item for item in findings if item.rule_id == rule_id)

    # The value travels through a variable without type or control-flow
    # information (or comes from local input), so confidence is capped at MEDIUM.
    assert finding.confidence is Confidence.MEDIUM
    assert finding.source is not None
    assert finding.source.line == 1
    assert finding.location.line == 2
    assert finding.flow[0].kind == "SOURCE"
    assert finding.flow[-1].kind == "SINK"


@pytest.mark.parametrize(
    "language, source",
    [
        ("PHP", "system('uptime');\n"),
        ("Java", 'Runtime.getRuntime().exec("uptime");\n'),
        ("C#", 'File.ReadAllText("settings.json");\n'),
        ("Go", 'http.Get("https://example.test/health")\n'),
        ("Ruby", "system('uptime')\n"),
        ("C", 'system("uptime");\n'),
        ("C++", 'system("uptime");\n'),
        ("Shell", "sh -c 'printf ok'\n"),
        ("PowerShell", "Get-Content ./settings.json\n"),
        ("Batch", "call fixed-command.cmd\n"),
    ],
)
def test_structured_language_rules_ignore_constant_sink_arguments(
    language: str,
    source: str,
) -> None:
    assert analyze_structured("app.txt", source, language) == []
