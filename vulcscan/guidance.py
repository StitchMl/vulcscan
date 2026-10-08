"""Deterministic, finding-aware remediation and verification guidance."""

from __future__ import annotations

import re
from dataclasses import replace

from .models import Confidence, Finding, Remediation
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
    contextual = _contextual_remediation(finding)
    if contextual is not None:
        concrete = [item for item in finding.remediations if item.suggested]
        remaining = [item for item in finding.remediations if not item.suggested]
        exact = [item for item in concrete if item.machine_applicable or "..." not in (item.suggested or "")]
        ordered = [*exact[:1], contextual, *concrete[:1], *remaining]
        finding.remediations = _mark_preferred(_unique_remediations(ordered)[:3])
    base = test_vectors_for(finding.rule_id)
    finding.test_vectors = _unique_text([*_contextual_vectors(finding), *base])


def _family(rule_id: str) -> str:
    return rule_id.split("-")[1] if rule_id.count("-") >= 2 else ""


def _contextual_remediation(finding: Finding) -> Remediation | None:
    family = _family(finding.rule_id)
    by_language = _FAMILY_PATCHES.get(family)
    if not by_language:
        return None
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
        return [
            f"On a disposable database, send `' OR '1'='1' -- ` through {target} using test-only rows. Compare it with an invalid value; authorization, row scope and response shape must stay unchanged.",
            f"Send a single quote `'` through {target}. The response must match an ordinary invalid value and expose no database error.",
            f"Send the paired predicates `1 AND 1=1` and `1 AND 1=2` through {target}. They must not change row count, authorization, status code or response shape.",
        ]
    if family == "CMD":
        marker = "%26 echo VULCSCAN_PROBE" if finding.language in {"Batch", "PowerShell"} else "; printf VULCSCAN_PROBE"
        return [f"On an isolated test instance, append `{marker}` through {target}. The marker must not appear in process output, files or logs as a command result."]
    if family == "XSS":
        return [f"Use `<img src=x onerror=console.log('VULCSCAN_PROBE')>` through {target} in a test browser. It must render as text or be removed; the console marker must not run."]
    if family == "PATH":
        return [f"Create a harmless canary outside the allowed test directory, then submit `../vulcscan-canary.txt` through {target}. The application must reject it without reading or overwriting the canary."]
    if family == "SSRF":
        return [f"Point {target} to `http://127.0.0.1:18080/vulcscan-probe` with a controlled listener. The listener must receive no request."]
    if family == "DESER":
        return [f"Send valid JSON with an unexpected field and malformed type metadata through {target}. The application must reject it before constructing application objects."]
    if family == "CODE":
        return [f"Send `1+1` through {target}. The application must preserve it as text and must not return or store the evaluated value `2`."]
    if finding.rule_id == "UPLOAD-MIME-001":
        return [f"Upload benign text as `vulcscan-probe.php.jpg` through {target} while declaring `image/jpeg`. Content inspection must reject it and no executable file may appear under the web root."]
    if finding.rule_id == "OPEN-REDIRECT-001":
        return [f"Submit `https://example.invalid/vulcscan-probe` through {target}. The response must not emit that external URL in `Location`."]
    if finding.rule_id in {"PY-XXE-001", "XXE-001"}:
        return [f"Send a DOCTYPE containing a nonexistent local canary entity through {target}. Parsing must fail before any external entity lookup."]
    base = test_vectors_for(finding.rule_id)
    if base:
        return [f"Exercise `{finding.sink}` at {finding.location.file}:{finding.location.line} on an isolated test deployment. {base[0]}"]
    return [f"Exercise the code path to `{finding.sink}` at {finding.location.file}:{finding.location.line} with boundary and malformed input. Confirm rejection causes no state change, outbound request or sensitive output."]


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
