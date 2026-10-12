"""Deterministic, finding-aware remediation and verification guidance."""

from __future__ import annotations

import json
import re
from dataclasses import replace

from .models import Confidence, Finding, Remediation
from .patch_guidance import computed_remediation
from .rules import test_vectors_for


_FAMILY_PATCHES: dict[str, dict[str, tuple[str, str]]] = {
    "SQL": {
        "Python": ("Bind the value with the active database driver's placeholder.", 'cursor.execute("SELECT ... WHERE field = ?", (value,))'),
        "JavaScript": ("Use the driver's bind array or named replacements.", 'await db.query("SELECT ... WHERE field = ?", [value]);'),
        "TypeScript": ("Use the driver's bind array or named replacements.", 'await db.query("SELECT ... WHERE field = ?", [value]);'),
        "PHP": ("Prepare constant SQL, bind the value, then execute.", '$stmt = $db->prepare("SELECT ... WHERE field = ?");\n$stmt->bind_param("s", $value);\n$stmt->execute();'),
        "Java": ("Prepare constant SQL and bind the value with its real JDBC type.", 'PreparedStatement ps = connection.prepareStatement("SELECT ... WHERE field = ?");\nps.setString(1, value);'),
        "C#": ("Use a typed provider parameter; do not use AddWithValue for ambiguous types.", 'command.CommandText = "SELECT ... WHERE field = @value";\ncommand.Parameters.Add("@value", SqlDbType.NVarChar, 128).Value = value;'),
        "Go": ("Keep the query constant and pass the value as a separate argument.", 'rows, err := db.QueryContext(ctx, "SELECT ... WHERE field = ?", value)'),
        "Ruby": ("Use an ORM predicate or a placeholder with a separate bind value.", 'Model.where(field: value)'),
        "PowerShell": ("Use a typed SqlParameter instead of interpolating the command text.", '$command.CommandText = "SELECT ... WHERE field = @value"\n$null = $command.Parameters.Add("@value", [Data.SqlDbType]::NVarChar, 128)\n$command.Parameters["@value"].Value = $value'),
        "C": ("Prepare the statement and bind the value with the database API.", 'sqlite3_prepare_v2(db, "SELECT ... WHERE field = ?", -1, &stmt, NULL);\nsqlite3_bind_text(stmt, 1, value, -1, SQLITE_TRANSIENT);'),
        "C++": ("Prepare the statement and bind the value with the database API.", 'sqlite3_prepare_v2(db, "SELECT ... WHERE field = ?", -1, &stmt, nullptr);\nsqlite3_bind_text(stmt, 1, value, -1, SQLITE_TRANSIENT);'),
    },
    "CMD": {
        "Python": ("Select the executable in code and pass one argument per list element.", 'subprocess.run([program, "--", value], shell=False, check=True)'),
        "JavaScript": ("Use execFile or spawn without a shell.", 'execFile(program, ["--", value], { shell: false });'),
        "TypeScript": ("Use execFile or spawn without a shell.", 'execFile(program, ["--", value], { shell: false });'),
        "PHP": ("Avoid the shell. Use a process API with an argument array.", '$process = new Process([$program, "--", $value]);\n$process->mustRun();'),
        "Java": ("Pass arguments as separate ProcessBuilder elements.", 'new ProcessBuilder(program, "--", value).start();'),
        "C#": ("Disable shell execution and add arguments through ArgumentList.", 'var start = new ProcessStartInfo(program) { UseShellExecute = false };\nstart.ArgumentList.Add("--");\nstart.ArgumentList.Add(value);'),
        "Go": ("Pass each argument separately; never invoke sh -c with input.", 'cmd := exec.CommandContext(ctx, program, "--", value)'),
        "Ruby": ("Use the array form so Ruby does not invoke a shell.", 'system(program, "--", value)'),
        "PowerShell": ("Map allowed operations to fixed commands and pass the value as one argument.", '& $allowedProgram -- $value'),
        "Shell": ("Quote data and select the command from a fixed case statement.", '"$allowed_program" -- "$value"'),
    },
    "XSS": {
        "Python": ("Keep the template fixed and let the framework escape the context value.", 'return render_template("page.html", value=value)'),
        "JavaScript": ("Return JSON, or escape for the exact HTML context before sending HTML.", 'res.json({ value });'),
        "TypeScript": ("Return JSON, or escape for the exact HTML context before sending HTML.", 'res.json({ value });'),
        "PHP": ("Encode HTML text and attribute values with UTF-8 error substitution.", "echo htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');"),
        "Java": ("Render through an auto-escaping template, or encode for the exact HTML context.", 'model.addAttribute("value", value); // fixed auto-escaped template'),
        "C#": ("Pass the value to a Razor view without Html.Raw.", 'return View("Page", new PageModel { Value = value });'),
        "Go": ("Use html/template and pass input as data, never template.HTML.", 'template.Must(template.ParseFiles("page.html")).Execute(w, data)'),
        "Ruby": ("Pass the value to an auto-escaping ERB/Rails template without raw or html_safe.", 'render :page, locals: { value: value }'),
    },
    "PATH": {
        "Python": ("Resolve both paths and reject candidates outside the fixed base.", 'candidate = (base / value).resolve()\nif base.resolve() not in candidate.parents:\n    raise ValueError("path outside base")'),
        "JavaScript": ("Resolve under a fixed base and enforce the separator-delimited prefix.", 'const candidate = path.resolve(base, value);\nif (!candidate.startsWith(path.resolve(base) + path.sep)) throw new Error("invalid path");'),
        "TypeScript": ("Resolve under a fixed base and enforce the separator-delimited prefix.", 'const candidate = path.resolve(base, value);\nif (!candidate.startsWith(path.resolve(base) + path.sep)) throw new Error("invalid path");'),
        "PHP": ("Resolve the parent and require it to stay under the fixed base.", '$candidate = realpath($base . DIRECTORY_SEPARATOR . $value);\nif ($candidate === false || !str_starts_with($candidate, realpath($base) . DIRECTORY_SEPARATOR)) { throw new RuntimeException("invalid path"); }'),
        "Java": ("Normalize the candidate and require it to start with the normalized base.", 'Path candidate = base.resolve(value).normalize();\nif (!candidate.startsWith(base.normalize())) throw new SecurityException("invalid path");'),
        "C#": ("Canonicalize and compare with the base plus a directory separator.", 'var candidate = Path.GetFullPath(Path.Combine(basePath, value));\nif (!candidate.StartsWith(Path.GetFullPath(basePath) + Path.DirectorySeparatorChar, StringComparison.Ordinal)) throw new InvalidOperationException();'),
        "Go": ("Clean the joined path and verify its relative path does not escape.", 'candidate := filepath.Clean(filepath.Join(base, value))\nrel, err := filepath.Rel(base, candidate)\nif err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) { return errInvalidPath }'),
        "Ruby": ("Expand the candidate under a fixed base and enforce containment.", 'candidate = File.expand_path(value, base)\nraise "invalid path" unless candidate.start_with?(File.expand_path(base) + File::SEPARATOR)'),
    },
    "SSRF": {
        "Python": ("Parse the URL and require HTTPS plus an exact host allowlist before the request.", 'url = urllib.parse.urlparse(value)\nif url.scheme != "https" or url.hostname not in ALLOWED_HOSTS:\n    raise ValueError("destination denied")'),
        "JavaScript": ("Parse first, then compare protocol and hostname as exact values.", 'const target = new URL(value);\nif (target.protocol !== "https:" || !ALLOWED_HOSTS.has(target.hostname)) throw new Error("destination denied");'),
        "TypeScript": ("Parse first, then compare protocol and hostname as exact values.", 'const target = new URL(value);\nif (target.protocol !== "https:" || !ALLOWED_HOSTS.has(target.hostname)) throw new Error("destination denied");'),
        "PHP": ("Parse the URL and compare scheme and host against exact allowlisted values.", '$parts = parse_url($value);\nif (($parts["scheme"] ?? "") !== "https" || !in_array($parts["host"] ?? "", $allowedHosts, true)) { throw new RuntimeException("destination denied"); }'),
        "Java": ("Parse into URI and compare scheme and host against exact allowlisted values.", 'URI target = URI.create(value);\nif (!"https".equals(target.getScheme()) || !allowedHosts.contains(target.getHost())) throw new SecurityException("destination denied");'),
        "C#": ("Require an absolute HTTPS URI with an exact allowlisted host.", 'if (!Uri.TryCreate(value, UriKind.Absolute, out var target) || target.Scheme != Uri.UriSchemeHttps || !allowedHosts.Contains(target.Host)) throw new InvalidOperationException();'),
        "Go": ("Parse the URL and compare scheme and hostname against exact allowlisted values.", 'target, err := url.Parse(value)\nif err != nil || target.Scheme != "https" || !allowedHosts[target.Hostname()] { return errDestinationDenied }'),
        "Ruby": ("Parse the URI and require HTTPS plus an exact host allowlist.", 'target = URI.parse(value)\nraise "destination denied" unless target.scheme == "https" && ALLOWED_HOSTS.include?(target.host)'),
    },
    "DESER": {
        "Python": ("Decode JSON into plain data and validate its shape.", 'data = json.loads(value)\nvalidate_schema(data)'),
        "JavaScript": ("Decode JSON and validate the resulting plain object against a schema.", 'const data = schema.parse(JSON.parse(value));'),
        "TypeScript": ("Decode JSON and validate the resulting plain object against a schema.", 'const data = schema.parse(JSON.parse(value));'),
        "PHP": ("Decode JSON as arrays and reject malformed input.", '$data = json_decode($value, true, 32, JSON_THROW_ON_ERROR);'),
        "Java": ("Deserialize into a fixed DTO type with polymorphic typing disabled.", 'RequestDto data = objectMapper.readValue(value, RequestDto.class);'),
        "C#": ("Deserialize into a sealed DTO type without type-name handling.", 'var data = JsonSerializer.Deserialize<RequestDto>(value);'),
        "Ruby": ("Decode JSON into plain hashes and arrays instead of loading Ruby objects.", 'data = JSON.parse(value)'),
    },
    "CODE": {
        "Python": ("Parse the expected data type; use literal_eval only for Python literals.", 'value = ast.literal_eval(input_text)'),
        "JavaScript": ("Parse JSON and dispatch operations through a fixed map.", 'const data = schema.parse(JSON.parse(inputText));'),
        "TypeScript": ("Parse JSON and dispatch operations through a fixed map.", 'const data = schema.parse(JSON.parse(inputText));'),
        "PHP": ("Parse JSON and map allowed operation names to fixed callables.", '$data = json_decode($input, true, 32, JSON_THROW_ON_ERROR);'),
        "C#": ("Parse into a fixed DTO and map operation names to fixed delegates.", 'var data = JsonSerializer.Deserialize<RequestDto>(input);'),
        "Ruby": ("Parse JSON and map operation names to fixed callables.", 'data = JSON.parse(input)'),
    },
}


def enrich_finding(finding: Finding) -> None:
    """Attach tailored, deterministic guidance without changing detection."""
    contextual = _contextual_remediation(finding) or _rule_specific_remediation(finding)
    if contextual is not None:
        concrete = [item for item in finding.remediations if item.suggested]
        remaining = [item for item in finding.remediations if not item.suggested]
        exact = [item for item in concrete if item.machine_applicable or "..." not in (item.suggested or "")]
        ordered = [*exact[:1], contextual, *concrete[:1], *remaining]
        finding.remediations = _mark_preferred(_unique_remediations(ordered)[:3])
    base = test_vectors_for(finding.rule_id)
    finding.test_vectors = _unique_text([*_contextual_vectors(finding), *base])


def _rule_specific_remediation(finding: Finding) -> Remediation | None:
    rule = finding.rule_id
    suggested: str | None = None
    title = f"Apply the safe form for {finding.sink}."
    confidence = Confidence.MEDIUM
    if rule == "PHP-URL-INCLUDE-001":
        suggested = re.sub(r"(?i)\bOn\b", "Off", finding.evidence, count=1)
        confidence = Confidence.HIGH
    elif rule == "DEBUG-001" and "=" in finding.evidence:
        key = finding.evidence.split("=", 1)[0].strip()
        suggested = f"{key} = Off"
        confidence = Confidence.HIGH
    elif rule == "DOCKER-ROOT-001":
        suggested = "RUN groupadd --system app && useradd --system --gid app --uid 10001 app\nUSER 10001:10001"
    elif rule == "SECRET-001":
        key = re.sub(r"[^A-Za-z0-9_]", "_", finding.sink).upper().strip("_") or "APP_SECRET"
        if finding.language == "Shell" and "mysql" in finding.evidence.casefold():
            suggested = 'mysql --defaults-extra-file="$MYSQL_CREDENTIALS_FILE" # file mode 0600, supplied at runtime'
        elif finding.language == "Environment":
            suggested = f"# Remove {key} from the committed file; inject it as a runtime secret named {key}."
        elif finding.language == "Dockerfile":
            suggested = f"# Remove ENV {key}=...; mount or inject {key} only when the container starts."
        else:
            suggested = f'{key} = os.environ["{key}"]'
    elif rule == "CSRF-001" and finding.language == "PHP":
        suggested = (
            "$_SESSION['csrf_token'] ??= bin2hex(random_bytes(32));\n"
            "if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {\n"
            "    http_response_code(403); exit;\n}"
        )
    elif rule == "DB-RACE-001":
        update = re.search(r"(?i)(UPDATE\s+\w+\s+SET\s+(\w+)\s*=\s*\2\s*-\s*1\s+WHERE\s+.+?)(?:[\";]|$)", finding.evidence)
        if update:
            sql, counter = update.group(1), update.group(2)
            suggested = f'{sql} AND {counter} > 0;\n# Accept success only when exactly one row was affected.'
    elif rule == "SESSION-FIXATION-001" and finding.language == "PHP":
        suggested = f"session_regenerate_id(true);\n{finding.evidence.strip()}"
        confidence = Confidence.HIGH
    elif rule == "UPLOAD-MIME-001" and finding.language == "PHP":
        field_match = re.search(r"\$_FILES\[['\"]([^'\"]+)", finding.evidence)
        field = field_match.group(1) if field_match else "upload"
        suggested = (
            f"$tmp = $_FILES['{field}']['tmp_name'];\n"
            "$mime = (new finfo(FILEINFO_MIME_TYPE))->file($tmp);\n"
            "if (!isset(['image/jpeg' => 'jpg', 'image/png' => 'png'][$mime])) { http_response_code(415); exit; }\n"
            "$safeName = bin2hex(random_bytes(16)) . '.' . ['image/jpeg' => 'jpg', 'image/png' => 'png'][$mime];\n"
            "move_uploaded_file($tmp, $nonExecutableUploadDir . DIRECTORY_SEPARATOR . $safeName);"
        )
    elif rule == "WEAK-HASH-001":
        suggested = re.sub(
            r"(?i)MD5\s*\([^)]*\)",
            "'<argon2id-hash-generated-by-the-application>'",
            finding.evidence,
            count=1,
        )
    elif rule == "CLEARTEXT-PASSWORD-001":
        suggested = (
            "INSERT INTO admin_users (username, password) VALUES "
            "('<test-user>', '<argon2id-hash-generated-by-the-application>');"
        )
    if suggested is None:
        return None
    existing = finding.remediations[0].guidance if finding.remediations else "Review the change against application policy."
    return Remediation(
        title=title,
        guidance=f"Reported evidence: {finding.evidence}. {existing}",
        preferred=True,
        patch_confidence=confidence,
        patch_risk="MEDIUM",
        current=finding.evidence or None,
        suggested=suggested,
        machine_applicable=False,
    )


def _family(rule_id: str) -> str:
    return rule_id.split("-")[1] if rule_id.count("-") >= 2 else ""


def _contextual_remediation(finding: Finding) -> Remediation | None:
    family = _family(finding.rule_id)
    by_language = _FAMILY_PATCHES.get(family)
    if not by_language:
        return None
    if family == "SQL":
        computed = _computed_sql_remediation(finding)
    elif finding.rule_id == "PHP-XSS-001":
        computed = _php_xss_remediation(finding)
    else:
        computed = computed_remediation(finding)
    if computed is not None:
        return computed
    patch = _php_sql_patch(finding) if family == "SQL" and finding.language == "PHP" else None
    patch = patch or by_language.get(finding.language)
    if patch is None:
        return None
    guidance, suggested = patch
    sink = _short_sink(finding.sink)
    return Remediation(
        title=f"Replace unsafe {sink} usage with the {finding.language} safe API pattern.",
        guidance=f"Reported sink: {finding.sink}. {guidance} Adapt names and types shown in the source-to-sink flow, then run the verification probes.",
        preferred=True,
        patch_confidence=Confidence.MEDIUM,
        patch_risk="MEDIUM",
        current=finding.evidence or None,
        suggested=suggested,
        machine_applicable=False,
    )


def _computed_sql_remediation(finding: Finding) -> Remediation | None:
    assignment = next(
        (
            step.code
            for step in reversed(finding.flow)
            if step.kind == "PROPAGATION" and re.search(r"(?i)\b(?:select|insert|update|delete)\b", step.code)
        ),
        None,
    )
    if assignment is None:
        return None
    match = re.match(
        r"^\s*(?:(?:const|let|var|final|String|string|auto)\s+|[A-Za-z_][\w<>,.?\[\]]*\s+)?"
        r"(?P<query>\$?[A-Za-z_]\w*)\s*(?::=|=)\s*(?P<expression>.+?)\s*;?\s*$",
        assignment,
        re.DOTALL,
    )
    if match is None:
        return None
    plan = _sql_binding_plan(match.group("expression"), finding.language)
    if plan is None:
        return None
    sql, values = plan
    suggested = _render_sql_patch(finding, sql, values)
    if suggested is None:
        return None
    value_names = ", ".join(f"`{value}`" for value in values)
    return Remediation(
        title=f"Parameterize the recovered query `{match.group('query')}`.",
        guidance=(
            f"The flow builds `{match.group('query')}` by concatenating {value_names}. "
            "Keep the recovered SQL constant and bind those values in the same order. "
            "Confirm the placeholder syntax and parameter types for the active database driver."
        ),
        preferred=True,
        patch_confidence=Confidence.HIGH,
        patch_risk="MEDIUM",
        current=assignment,
        suggested=suggested,
        machine_applicable=False,
    )


def _sql_binding_plan(expression: str, language: str) -> tuple[str, list[str]] | None:
    separator = "." if language == "PHP" else "+"
    parts = _split_string_expression(expression, separator)
    if not parts or len(parts) < 3:
        return None
    decoded: list[str | None] = [_quoted_text(part) for part in parts]
    sql = ""
    values: list[str] = []
    index = 0
    while index < len(parts):
        literal = decoded[index]
        if literal is not None:
            sql += literal
            index += 1
            continue
        value = parts[index].strip()
        if not re.fullmatch(r"\$?[A-Za-z_]\w*(?:\[[^\]]+\]|\.[A-Za-z_]\w*)*", value):
            return None
        following = decoded[index + 1] if index + 1 < len(parts) else None
        if following is not None and sql.endswith(("'", '"')) and following.startswith(sql[-1]):
            sql = sql[:-1]
            decoded[index + 1] = following[1:]
        sql += "?"
        values.append(value)
        index += 1
    if not values or not re.search(r"(?i)\b(?:select|insert|update|delete)\b", sql):
        return None
    return sql, values


def _split_string_expression(expression: str, separator: str) -> list[str] | None:
    parts: list[str] = []
    start = 0
    quote = ""
    escaped = False
    for index, char in enumerate(expression):
        if escaped:
            escaped = False
            continue
        if char == "\\" and quote:
            escaped = True
            continue
        if char in {"'", '"', "`"}:
            quote = "" if quote == char else char if not quote else quote
            continue
        if char == separator and not quote:
            parts.append(expression[start:index].strip())
            start = index + 1
    if quote:
        return None
    parts.append(expression[start:].strip())
    return parts if all(parts) else None


def _quoted_text(value: str) -> str | None:
    value = value.strip()
    if len(value) < 2 or value[0] not in {"'", '"', "`"} or value[-1] != value[0]:
        return None
    body = value[1:-1]
    return body.replace("\\" + value[0], value[0]).replace("\\\\", "\\")


def _render_sql_patch(finding: Finding, sql: str, values: list[str]) -> str | None:
    encoded = json.dumps(sql)
    joined = ", ".join(values)
    call = re.search(r"([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)+)\s*\(", finding.evidence)
    callee = re.sub(r"\s+", "", call.group(1)) if call else "db.execute"
    if finding.language == "Python":
        tuple_values = joined + ("," if len(values) == 1 else "")
        return f"{callee}({encoded}, ({tuple_values}))"
    if finding.language in {"JavaScript", "TypeScript"}:
        return f"await {callee}({encoded}, [{joined}]);"
    if finding.language == "Go":
        return f"{callee}({encoded}, {joined})"
    if finding.language == "Ruby":
        return f"{callee}({encoded}, [{joined}])"
    if finding.language == "Java":
        setters = "\n".join(f"statement.setObject({index}, {value});" for index, value in enumerate(values, 1))
        return f"PreparedStatement statement = connection.prepareStatement({encoded});\n{setters}\nResultSet rows = statement.executeQuery();"
    if finding.language == "C#":
        named_sql = sql
        for index in range(len(values)):
            named_sql = named_sql.replace("?", f"@p{index}", 1)
        parameters = "\n".join(
            f'command.Parameters.Add("@p{index}", SqlDbType.NVarChar, 256).Value = {value};'
            for index, value in enumerate(values)
        )
        return f"command.CommandText = {json.dumps(named_sql)};\n{parameters}\nvar rows = command.ExecuteReader();"
    return None


def _php_sql_patch(finding: Finding) -> tuple[str, str] | None:
    """Build a mysqli review template from a simple concatenated query assignment."""
    assignment = next(
        (
            step.code
            for step in reversed(finding.flow)
            if step.kind == "PROPAGATION" and re.match(r"^\s*\$[A-Za-z_]\w*\s*=", step.code)
        ),
        None,
    )
    if assignment is None:
        return None
    match = re.match(r"^\s*(\$[A-Za-z_]\w*)\s*=\s*(.+?)\s*;?\s*$", assignment)
    if match is None:
        return None
    parts = _split_php_concat(match.group(2))
    if not parts:
        return None
    sql = ""
    values: list[str] = []
    index = 0
    while index < len(parts):
        part = parts[index].strip()
        literal = _php_string(part)
        if literal is not None:
            sql += literal
            index += 1
            continue
        if not re.fullmatch(r"\$[A-Za-z_]\w*", part):
            return None
        following = _php_string(parts[index + 1].strip()) if index + 1 < len(parts) else None
        if following is not None and sql.endswith("'%") and following.startswith("%'"):
            sql = sql[:-2] + "?"
            parts[index + 1] = repr(following[2:])
            values.append(f'"%" . {part} . "%"')
        elif following is not None and sql.endswith(("'", '"')) and following.startswith(sql[-1]):
            quote = sql[-1]
            sql = sql[:-1] + "?"
            parts[index + 1] = repr(following[1:] if following.startswith(quote) else following)
            values.append(part)
        else:
            sql += "?"
            values.append(part)
        index += 1
    if not values:
        return None
    escaped_sql = sql.replace("\\", "\\\\").replace('"', '\\"')
    bind_types = "s" * len(values)
    suggested = (
        f'$stmt = $db->prepare("{escaped_sql}");\n'
        f'$stmt->bind_param("{bind_types}", {", ".join(values)});\n'
        "$stmt->execute();\n$result = $stmt->get_result();"
    )
    return (
        f"The flow builds {match.group(1)} from {', '.join(values)}. Keep its SQL text constant and bind those values in the same order; confirm the receiver is the reported mysqli connection.",
        suggested,
    )


def _php_xss_remediation(finding: Finding) -> Remediation | None:
    match = re.match(r"^\s*echo\s+(.+?)\s*;?\s*$", finding.evidence, re.DOTALL)
    if match is None:
        return None
    parts = _split_php_concat(match.group(1))
    if not parts:
        return None
    changed = False
    safe_parts: list[str] = []
    for part in parts:
        stripped = part.strip()
        if _php_string(stripped) is not None or re.match(r"(?i)^htmlspecialchars\s*\(", stripped):
            safe_parts.append(stripped)
            continue
        if not re.search(r"\$[A-Za-z_]", stripped):
            return None
        safe_parts.append(f"htmlspecialchars({stripped}, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')")
        changed = True
    if not changed:
        return None
    return Remediation(
        title="Encode the untrusted PHP expressions while preserving the recovered markup.",
        guidance=(
            f"The output expression at `{finding.sink}` mixes markup with request or stored data. "
            "Keep literal markup unchanged and HTML-encode each dynamic expression at output time."
        ),
        preferred=True,
        patch_confidence=Confidence.HIGH,
        patch_risk="LOW",
        current=finding.evidence,
        suggested="echo " + " . ".join(safe_parts) + ";",
        machine_applicable=False,
    )


def _split_php_concat(expression: str) -> list[str] | None:
    parts: list[str] = []
    start = 0
    quote = ""
    escaped = False
    for index, char in enumerate(expression):
        if escaped:
            escaped = False
            continue
        if char == "\\" and quote:
            escaped = True
            continue
        if char in {"'", '"'}:
            quote = "" if quote == char else char if not quote else quote
            continue
        if char == "." and not quote:
            parts.append(expression[start:index].strip())
            start = index + 1
    if quote:
        return None
    parts.append(expression[start:].strip())
    return parts if all(parts) else None


def _php_string(value: str) -> str | None:
    if len(value) < 2 or value[0] not in {"'", '"'} or value[-1] != value[0]:
        return None
    body = value[1:-1]
    return body.replace("\\" + value[0], value[0]).replace("\\\\", "\\")


def _contextual_vectors(finding: Finding) -> list[str]:
    family = _family(finding.rule_id)
    target = f"the input that reaches `{finding.sink}` at {finding.location.file}:{finding.location.line}"
    if family == "SQL":
        symbols = _traced_symbols(finding)
        if symbols:
            rendered = " -> ".join(f"`{symbol}`" for symbol in symbols)
            target = f"the traced flow {rendered} reaching `{finding.sink}` at {finding.location.file}:{finding.location.line}"
        return [
            *_sql_proof_vectors(finding, target),
            f"On a disposable database, send `' OR '1'='1' -- ` through {target} using test-only rows. Compare it with an invalid value; authorization, row scope and response shape must stay unchanged.",
            f"Send a single quote `'` through {target}. The response must match an ordinary invalid value and expose no database error.",
            f"Send the paired predicates `1 AND 1=1` and `1 AND 1=2` through {target}. They must not change row count, authorization, status code or response shape.",
        ]
    if family == "CMD":
        payload, channel = _command_probe(finding)
        return [
            f"Command-execution proof for traced value `{_traced_value(finding)}`: send `{payload}` through {target}. "
            f"On an isolated instance, `{channel}` must contain no `VULCSCAN_CMD_` marker generated by a second command."
        ]
    if family == "XSS":
        payload, context = _xss_probe(finding)
        return [
            f"XSS proof for traced value `{_traced_value(finding)}` in {context}: send `{payload}` through {target}. "
            "Open only the isolated test page. The browser console must contain no `VULCSCAN_XSS` marker."
        ]
    if family == "PATH":
        payload = _path_probe(finding)
        return [
            f"Path-escape proof for traced value `{_traced_value(finding)}`: place a harmless file named `vulcscan-canary.txt` "
            f"one directory above the configured base, then send `{payload}` through {target}. The response, download, logs and target directory must expose no canary content or write."
        ]
    if family == "SSRF":
        primary, alternate = _ssrf_probes(finding)
        return [
            f"SSRF proof for traced value `{_traced_value(finding)}`: run a controlled HTTP listener on loopback, then send `{primary}` through {target}. "
            f"If the code normalizes hosts, repeat with `{alternate}`. No listener request carrying `VULCSCAN_SSRF` may arrive."
        ]
    if family == "DESER":
        payload, proof = _deserialization_probe(finding)
        return [
            f"Deserialization proof for `{_short_sink(finding.sink)}` and traced value `{_traced_value(finding)}`: {payload} through {target}. "
            f"The parser must reject it before object construction; {proof}"
        ]
    if family == "CODE":
        payload, proof = _code_probe(finding)
        return [
            f"Code-evaluation proof for traced value `{_traced_value(finding)}`: send `{payload}` through {target}. "
            f"{proof} must contain no `VULCSCAN_CODE` marker; the application must treat the payload as data."
        ]
    if finding.rule_id == "UPLOAD-MIME-001":
        name, content, declared = _upload_probe(finding)
        return [
            f"Upload-validation proof for `{_short_sink(finding.sink)}`: upload `{name}` through {target}, declare `{declared}`, and use harmless content `{content}`. "
            "The server must reject the mismatch. No public URL or executable file may contain `VULCSCAN_UPLOAD`."
        ]
    if finding.rule_id == "OPEN-REDIRECT-001":
        payload = _redirect_probe(finding)
        return [
            f"Redirect proof for traced value `{_traced_value(finding)}`: submit `{payload}` through {target} without following redirects. "
            "The status and `Location` header must keep navigation on the expected origin and must not contain `vulcscan-redirect.example`."
        ]
    if finding.rule_id in {"PY-XXE-001", "XXE-001"}:
        return [f"Send a DOCTYPE containing a nonexistent local canary entity through {target}. Parsing must fail before any external entity lookup."]
    base = test_vectors_for(finding.rule_id)
    if base:
        return [f"Exercise `{finding.sink}` at {finding.location.file}:{finding.location.line} on an isolated test deployment. {base[0]}"]
    return [f"Exercise the code path to `{finding.sink}` at {finding.location.file}:{finding.location.line} with boundary and malformed input. Confirm rejection causes no state change, outbound request or sensitive output."]


def _traced_value(finding: Finding) -> str:
    """Recover the source variable or expression named by the data-flow trace."""
    steps = [step for step in finding.flow if step.kind in {"SOURCE", "PROPAGATION"}]
    for step in reversed(steps):
        code = step.code.strip()
        assignment = re.match(
            r"^(?:const\s+|let\s+|var\s+|String\s+|string\s+|auto\s+)?([@$]?[A-Za-z_]\w*)\s*(?::=|=)",
            code,
        )
        if assignment:
            return assignment.group(1)
        source = re.search(
            r"(?:request\.(?:args|form|values)|req\.(?:query|body|params)|params|_GET|_POST|Query\(\)|FormValue)\s*(?:\[|\.|\()\s*['\"]?([A-Za-z_]\w*)",
            code,
            re.IGNORECASE,
        )
        if source:
            return source.group(1)
    evidence_arg = re.search(r"\(([^(),]+)\)", finding.evidence or "")
    return evidence_arg.group(1).strip()[:80] if evidence_arg else "remote input"


def _traced_symbols(finding: Finding) -> list[str]:
    """Recover concrete assignment names in source-to-sink order."""
    symbols: list[str] = []
    for step in finding.flow:
        if step.kind not in {"SOURCE", "PROPAGATION"}:
            continue
        match = re.match(
            r"^\s*(?:(?:const|let|var|final|String|string|auto)\s+|"
            r"[A-Za-z_][\w<>,.?\[\]]*\s+)?"
            r"(?P<name>\$?[A-Za-z_]\w*)\s*(?::=|=|\+=|\.=)",
            step.code,
        )
        if match and match.group("name") not in symbols:
            symbols.append(match.group("name"))
    return symbols


def _context_text(finding: Finding) -> str:
    return "\n".join([finding.evidence, finding.sink, *(step.code for step in finding.flow)])


def _command_probe(finding: Finding) -> tuple[str, str]:
    text = _context_text(finding).casefold()
    if finding.language == "PowerShell" or any(token in text for token in ("invoke-expression", "powershell")):
        return "; Write-Output VULCSCAN_CMD_$PID #", "captured output or PowerShell transcript"
    if finding.language == "Batch" or any(token in text for token in ("cmd.exe", "%comspec%", "call %")):
        return "& echo VULCSCAN_CMD_%RANDOM% & rem ", "captured output or process log"
    if finding.language in {"C#"} and re.search(r"(?i)cmd(?:\.exe)?|/c\b", text):
        return "& echo VULCSCAN_CMD_%RANDOM% & rem ", "captured output or process log"
    return "; printf 'VULCSCAN_CMD_%s\\n' \"$$\"; #", "captured stdout or process log"


def _xss_probe(finding: Finding) -> tuple[str, str]:
    text = _context_text(finding)
    if re.search(r"(?is)<script\b|javascript\s*:|script(?:text|content)", text):
        return "';console.log('VULCSCAN_XSS');//", "a JavaScript string/script context"
    if re.search(r"(?is)(?:href|src|action|value|data-[\w-]+)\s*=|setAttribute\s*\(", text):
        return '\" autofocus onfocus=console.log(\'VULCSCAN_XSS\') x=\"', "an HTML attribute context"
    return "<img src=x onerror=console.log('VULCSCAN_XSS')>", "an HTML text context"


def _path_probe(finding: Finding) -> str:
    text = _context_text(finding)
    windows = finding.language in {"C#", "PowerShell", "Batch"} or bool(re.search(r"[A-Za-z]:\\|\\\\", text))
    return r"..\vulcscan-canary.txt" if windows else "../vulcscan-canary.txt"


def _ssrf_probes(finding: Finding) -> tuple[str, str]:
    text = _context_text(finding)
    if re.search(r"(?i)(?:baseurl|urljoin|resolve\s*\(|new\s+url\s*\()", text):
        return "//127.0.0.1:18080/VULCSCAN_SSRF", "http://[::1]:18080/VULCSCAN_SSRF"
    return "http://127.0.0.1:18080/VULCSCAN_SSRF", "http://[::1]:18080/VULCSCAN_SSRF"


def _deserialization_probe(finding: Finding) -> tuple[str, str]:
    text = _context_text(finding).casefold()
    if finding.language == "Python" and any(name in text for name in ("pickle.load", "pickle.loads")):
        return "generate a pickle whose `__reduce__` target is `builtins.print` with argument `VULCSCAN_DESER`, then send its bytes", "stdout and logs must contain no `VULCSCAN_DESER` marker."
    if finding.language in {"JavaScript", "TypeScript", "Java", "C#"}:
        return 'send `{"$type":"VULCSCAN_DESER","@type":"VULCSCAN_DESER","value":"canary"}` as valid JSON', "no runtime type lookup, constructor error or canary object may appear in logs."
    if finding.language == "PHP":
        return 'send `O:8:"stdClass":1:{s:6:"marker";s:15:"VULCSCAN_DESER";}`', "the application must not create or expose the marker property."
    if finding.language == "Ruby":
        return "send an isolated Marshal payload containing the plain string `VULCSCAN_DESER`", "the endpoint must not accept Marshal object data from the request."
    return "send valid structured data carrying type metadata and marker `VULCSCAN_DESER`", "logs and output must show neither type resolution nor object construction."


def _code_probe(finding: Finding) -> tuple[str, str]:
    language = finding.language
    if language == "Python":
        return "(__import__('builtins').print('VULCSCAN_CODE'),0)[1]", "captured stdout and logs"
    if language in {"JavaScript", "TypeScript"}:
        return "console.log('VULCSCAN_CODE'),0", "browser/server console and logs"
    if language == "PHP":
        return "print('VULCSCAN_CODE') or 0", "response and logs"
    if language == "Ruby":
        return "puts('VULCSCAN_CODE'); 0", "captured stdout and logs"
    if language == "PowerShell":
        return "Write-Output VULCSCAN_CODE_$PID", "captured output and transcript"
    return "1+1", "response, stored value and logs"


def _upload_probe(finding: Finding) -> tuple[str, str, str]:
    text = _context_text(finding).casefold()
    if finding.language == "PHP" or ".php" in text:
        return "vulcscan-probe.php.jpg", "<?php /* VULCSCAN_UPLOAD */ ?>", "image/jpeg"
    if finding.language in {"JavaScript", "TypeScript"} or "node" in text:
        return "vulcscan-probe.js.png", "/* VULCSCAN_UPLOAD */", "image/png"
    if finding.language == "Python":
        return "vulcscan-probe.py.png", "# VULCSCAN_UPLOAD", "image/png"
    return "vulcscan-probe.html.jpg", "<!-- VULCSCAN_UPLOAD -->", "image/jpeg"


def _redirect_probe(finding: Finding) -> str:
    text = _context_text(finding)
    if re.search(r"(?i)(?:urljoin|resolve\s*\(|new\s+url\s*\(|startsWith\s*\(\s*['\"]\/)", text):
        return "//vulcscan-redirect.example/VULCSCAN_REDIRECT"
    return "https://vulcscan-redirect.example/VULCSCAN_REDIRECT"


def _sql_proof_vectors(finding: Finding, target: str) -> list[str]:
    """Return data-bearing SQL probes when the traced query shape is recoverable."""
    statement = _sql_flow_expression(finding)
    if statement is None:
        return []
    lowered = statement.casefold()
    if "select" in lowered and re.search(r"\b(?:password|passwd|credential|secret|token)\b", lowered):
        return [
            f"Authentication proof: submit `' OR 1=1 -- ` through {target} and use a deliberately invalid password in every other field. A privileged session, redirect or protected page proves an authorization bypass. Record only the test account/session identifier."
        ]
    shape = _select_shape(statement)
    if shape is None:
        if "select" in lowered and "where" in lowered:
            return [_row_scope_proof(target)]
        return []
    columns = shape
    marker_index = next(
        (
            index
            for index, name in enumerate(columns)
            if not re.search(r"(?i)(?:^|_)(?:id|count|price|amount|total|number|qty|quantity)(?:_|$)", name)
        ),
        0,
    )
    values = ["NULL"] * len(columns)
    values[marker_index] = "CURRENT_USER"
    string_payload = "' UNION SELECT " + ",".join(values) + " -- "
    numeric_payload = "0 UNION SELECT " + ",".join(values) + " -- "
    return [
        _row_scope_proof(target),
        f"Database-read proof: the traced SELECT has {len(columns)} output columns. Submit `{string_payload}` for a quoted value, or `{numeric_payload}` for a numeric value, through {target}. A database principal rendered in output column {marker_index + 1} proves that injected SQL read data outside the intended query. `CURRENT_USER` works on major SQL engines; use the engine's read-only identity function when unsupported. Use only disposable test data.",
    ]


def _sql_flow_expression(finding: Finding) -> str | None:
    for step in reversed(finding.flow):
        if step.kind != "PROPAGATION" or not re.search(r"(?i)\bselect\b", step.code):
            continue
        match = re.match(r"^\s*\$?[A-Za-z_]\w*\s*=\s*(.+?)\s*;?\s*$", step.code, re.DOTALL)
        return match.group(1) if match else step.code
    return None


def _row_scope_proof(target: str) -> str:
    return (
        f"Unauthorized-row proof: submit `' OR 1=1 -- ` for a quoted value or `0 OR 1=1 -- ` for a numeric value through {target}. "
        "Compare stable record identifiers with a request made by the least-privileged test account. Any row outside that account's normal tenant, owner or filter scope proves unauthorized data retrieval."
    )


def _select_shape(expression: str) -> list[str] | None:
    """Recover a simple SELECT list from source in any supported language."""
    match = re.search(r"(?is)\bSELECT\s+(.+?)\s+FROM\b", expression)
    if not match or "*" in match.group(1):
        return None
    raw_columns = match.group(1).strip().lstrip("'\"`")
    columns = [item.strip().rsplit(".", 1)[-1].strip("`\"[] ") for item in raw_columns.split(",")]
    if not 1 <= len(columns) <= 20 or any(not re.fullmatch(r"[A-Za-z_]\w*", item) for item in columns):
        return None
    return columns


def _short_sink(sink: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.:-]+", " ", sink).strip()
    return cleaned[:72] or "sink"


def _unique_remediations(items: list[Remediation]) -> list[Remediation]:
    seen: set[tuple[str, str | None]] = set()
    result: list[Remediation] = []
    for item in items:
        key = (item.title, item.suggested)
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


def _mark_preferred(items: list[Remediation]) -> list[Remediation]:
    return [replace(item, preferred=index == 0) for index, item in enumerate(items)]


def _unique_text(items: list[str]) -> list[str]:
    return list(dict.fromkeys(item for item in items if item))
