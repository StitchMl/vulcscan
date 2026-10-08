"""Computed review patches built from a finding's evidence and data-flow."""

from __future__ import annotations

import re

from .models import Confidence, Finding, Remediation

_SUPPORTED = frozenset({"CMD", "XSS", "PATH", "SSRF", "DESER", "CODE"})


def computed_remediation(finding: Finding) -> Remediation | None:
    """Return a sink-aware patch that preserves names recovered from the finding."""
    family = _family(finding.rule_id)
    if family not in _SUPPORTED:
        return None
    expression = _tainted_expression(finding)
    if expression is None:
        return None
    rendered = _render(family, finding.language, expression, finding.evidence)
    if rendered is None:
        return None
    guidance, suggested = rendered
    return Remediation(
        title=f"Replace {finding.sink} using the traced value `{expression}`.",
        guidance=(
            f"The flow shows `{expression}` reaching `{finding.sink}`. {guidance} "
            "Review framework imports, response semantics and application policy before applying."
        ),
        preferred=True,
        patch_confidence=Confidence.MEDIUM,
        patch_risk="MEDIUM",
        current=finding.evidence or None,
        suggested=suggested,
        machine_applicable=False,
    )


def _family(rule_id: str) -> str:
    return rule_id.split("-")[1] if rule_id.count("-") >= 2 else ""


def _tainted_expression(finding: Finding) -> str | None:
    evidence = finding.evidence.strip()
    arguments = _call_arguments(evidence)
    names = _flow_names(finding)
    if arguments:
        matching = [item for item in arguments if any(_contains_name(item, name) for name in names)]
        if matching:
            return _clean_expression(matching[-1])
        index = _sink_argument_index(finding, evidence, len(arguments))
        if index is not None:
            return _clean_expression(arguments[index])
    assignment = re.search(r"(?s)(?:\.\s*CommandText\s*=|\b(?:include|require)(?:_once)?\s+)\s*(.+?);?$", evidence)
    if assignment:
        return _clean_expression(assignment.group(1))
    for name in reversed(names):
        if _contains_name(evidence, name):
            return name
    source = next((step.code.strip() for step in finding.flow if step.kind == "SOURCE"), "")
    return _clean_expression(source) if source and len(source) <= 120 else None


def _flow_names(finding: Finding) -> list[str]:
    names: list[str] = []
    for step in finding.flow:
        code = step.code.strip()
        match = re.match(
            r"(?:const\s+|let\s+|var\s+|final\s+|[\w<>,.?\[\]]+\s+)?"
            r"(?P<name>\$?[A-Za-z_]\w*)\s*(?::=|=|\+=|\.=)",
            code,
        )
        if match:
            names.append(match.group("name"))
        elif re.fullmatch(r"\$?[A-Za-z_]\w*", code):
            names.append(code)
    unique: list[str] = []
    for name in names:
        if name not in unique:
            unique.append(name)
    return unique


def _contains_name(text: str, name: str) -> bool:
    return re.search(rf"(?<![\w$]){re.escape(name)}(?!\w)", text) is not None


def _call_arguments(text: str) -> list[str]:
    open_index = text.find("(")
    if open_index < 0:
        return []
    close_index = _matching_close(text, open_index)
    if close_index < 0:
        return []
    return _split_arguments(text[open_index + 1 : close_index])


def _matching_close(text: str, open_index: int) -> int:
    depth = 0
    quote = ""
    escaped = False
    for index in range(open_index, len(text)):
        char = text[index]
        if escaped:
            escaped = False
            continue
        if char == "\\" and quote:
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = ""
            continue
        if char in {"'", '"', "`"}:
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
    return -1


def _split_arguments(body: str) -> list[str]:
    parts: list[str] = []
    start = 0
    depth = 0
    quote = ""
    escaped = False
    pairs = {"(": ")", "[": "]", "{": "}"}
    stack: list[str] = []
    for index, char in enumerate(body):
        if escaped:
            escaped = False
            continue
        if char == "\\" and quote:
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = ""
            continue
        if char in {"'", '"', "`"}:
            quote = char
        elif char in pairs:
            stack.append(pairs[char])
            depth += 1
        elif stack and char == stack[-1]:
            stack.pop()
            depth -= 1
        elif char == "," and depth == 0:
            parts.append(body[start:index].strip())
            start = index + 1
    tail = body[start:].strip()
    if tail:
        parts.append(tail)
    return parts


def _sink_argument_index(finding: Finding, evidence: str, count: int) -> int | None:
    if count == 0:
        return None
    compact = evidence.casefold()
    if finding.language == "Go" and "newrequestwithcontext" in compact:
        return 2 if count > 2 else None
    if finding.language == "Go" and "newrequest" in compact:
        return 1 if count > 1 else None
    if finding.language == "Go" and re.search(r"fmt\s*\.\s*fprint", compact):
        return count - 1 if count > 1 else None
    if finding.language == "PHP" and re.search(r"\b(?:mysqli_query|pg_query|curl_setopt)\b", compact):
        return count - 1
    if finding.language == "JavaScript" and re.search(r"\b(?:writefile|copyfile|rename)\w*\s*\(", compact):
        return min(1, count - 1)
    return 0


def _clean_expression(value: str) -> str | None:
    value = value.strip().rstrip(";").strip()
    if not value or len(value) > 180 or value in {"null", "None", "nil"}:
        return None
    return value


def _render(family: str, language: str, value: str, evidence: str) -> tuple[str, str] | None:
    renderer = {
        "CMD": _command_patch,
        "XSS": _xss_patch,
        "PATH": _path_patch,
        "SSRF": _ssrf_patch,
        "DESER": _deser_patch,
        "CODE": _code_patch,
    }[family]
    return renderer(language, value, evidence)


def _command_patch(language: str, value: str, _evidence: str) -> tuple[str, str] | None:
    program, fixed_arguments, argument = _command_parts(value)
    input_value = argument or value
    program_value = _quote(program) if program else "ALLOWED_PROGRAM"
    arguments = [*(_quote(item) for item in fixed_arguments), input_value]
    if not fixed_arguments:
        arguments.insert(0, '"--"')
    rendered_arguments = ", ".join(arguments)
    patches = {
        "Python": f"subprocess.run([{program_value}, {rendered_arguments}], shell=False, check=True)",
        "JavaScript": f"execFile({program_value}, [{rendered_arguments}], {{ shell: false }});",
        "TypeScript": f"execFile({program_value}, [{rendered_arguments}], {{ shell: false }});",
        "PHP": f"$process = new Process([{program_value}, {rendered_arguments}]);\n$process->mustRun();",
        "Java": f"new ProcessBuilder({program_value}, {rendered_arguments}).start();",
        "C#": f"var start = new ProcessStartInfo({program_value}) {{ UseShellExecute = false }};\n" + "\n".join(f"start.ArgumentList.Add({item});" for item in arguments) + "\nProcess.Start(start);",
        "Go": f"cmd := exec.CommandContext(ctx, {program_value}, {rendered_arguments})",
        "Ruby": f"system({program_value}, {rendered_arguments})",
        "PowerShell": f"& {program_value} -- {input_value}",
        "Shell": f"{program_value} -- \"{input_value.strip('$')}\"",
    }
    suggested = patches.get(language)
    if suggested is None:
        return None
    detail = f"The fixed executable is `{program}`; pass `{input_value}` as one argument." if program else f"Choose the executable from an allowlist and pass `{input_value}` as one argument."
    return detail + " Do not invoke a command shell.", suggested


def _command_parts(expression: str) -> tuple[str | None, list[str], str | None]:
    match = re.match(
        r'''^\s*["'](?P<prefix>[\w./\\-]+(?:\s+[\w./\\-]+)*)\s+["']\s*(?:\+|\.)\s*(?P<arg>.+)$''',
        expression,
    )
    if match:
        tokens = match.group("prefix").split()
        return tokens[0], tokens[1:], match.group("arg").strip()
    program, argument = _command_shape(expression)
    return program, [], argument


def _command_shape(expression: str) -> tuple[str | None, str | None]:
    patterns = (
        r'''^\s*["'](?P<program>[\w./\\-]+)\s+["']\s*(?:\+|\.)\s*(?P<arg>.+)$''',
        r'''^\s*[fF]?["'](?P<program>[\w./\\-]+)\s+\{(?P<arg>[^{}]+)\}["']\s*$''',
        r'''^\s*`(?P<program>[\w./\\-]+)\s+\$\{(?P<arg>[^{}]+)\}`\s*$''',
    )
    for pattern in patterns:
        match = re.match(pattern, expression)
        if match:
            return match.group("program"), match.group("arg").strip()
    return None, None


def _xss_patch(language: str, value: str, _evidence: str) -> tuple[str, str] | None:
    patches = {
        "Python": f"return render_template(\"page.html\", value={value})",
        "JavaScript": f"res.send(escapeHtml({value}));",
        "TypeScript": f"res.send(escapeHtml({value}));",
        "PHP": f"echo htmlspecialchars({value}, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');",
        "Java": f"response.getWriter().print(Encode.forHtml({value}));",
        "C#": f"await Response.WriteAsync(HtmlEncoder.Default.Encode({value}));",
        "Go": f"fmt.Fprint(w, html.EscapeString({value}))",
        "Ruby": f"ERB::Util.html_escape({value})",
    }
    suggested = patches.get(language)
    if suggested is None:
        return None
    return "Encode the traced value for the HTML text context. Use a context-specific encoder for attributes, URLs, CSS or JavaScript.", suggested


def _path_patch(language: str, value: str, evidence: str) -> tuple[str, str] | None:
    base = _path_base(value) or _path_base(evidence)
    input_value = _path_input(value) or value
    base_value = _quote(base) if base else "ALLOWED_BASE"
    patches = {
        "Python": f"base = Path({base_value}).resolve()\ncandidate = (base / {input_value}).resolve()\nif base not in candidate.parents:\n    raise ValueError(\"path outside base\")",
        "JavaScript": f"const base = path.resolve({base_value});\nconst candidate = path.resolve(base, {input_value});\nif (!candidate.startsWith(base + path.sep)) throw new Error(\"path outside base\");",
        "TypeScript": f"const base = path.resolve({base_value});\nconst candidate = path.resolve(base, {input_value});\nif (!candidate.startsWith(base + path.sep)) throw new Error(\"path outside base\");",
        "PHP": f"$base = realpath({base_value});\n$candidate = realpath($base . DIRECTORY_SEPARATOR . {input_value});\nif ($candidate === false || !str_starts_with($candidate, $base . DIRECTORY_SEPARATOR)) {{ throw new RuntimeException('path outside base'); }}",
        "Java": f"Path base = Path.of({base_value}).toRealPath();\nPath candidate = base.resolve({input_value}).normalize();\nif (!candidate.startsWith(base)) throw new SecurityException(\"path outside base\");",
        "C#": f"var basePath = Path.GetFullPath({base_value});\nvar candidate = Path.GetFullPath(Path.Combine(basePath, {input_value}));\nif (!candidate.StartsWith(basePath + Path.DirectorySeparatorChar, StringComparison.Ordinal)) throw new InvalidOperationException();",
        "Go": f"base := filepath.Clean({base_value})\ncandidate := filepath.Clean(filepath.Join(base, {input_value}))\nrel, err := filepath.Rel(base, candidate)\nif err != nil || rel == \"..\" || strings.HasPrefix(rel, \"..\"+string(filepath.Separator)) {{ return errInvalidPath }}",
        "Ruby": f"base = File.realpath({base_value})\ncandidate = File.expand_path({input_value}, base)\nraise \"path outside base\" unless candidate.start_with?(base + File::SEPARATOR)",
    }
    suggested = patches.get(language)
    if suggested is None:
        return None
    detail = f"Canonicalize against the recovered base `{base}`" if base else "Set `ALLOWED_BASE` to the directory owned by this feature"
    return f"{detail}, then reject any path outside it before calling `{_callee(evidence)}`.", suggested


def _ssrf_patch(language: str, value: str, evidence: str) -> tuple[str, str] | None:
    patches = {
        "Python": f"target = urllib.parse.urlparse({value})\nif target.scheme != \"https\" or target.hostname not in ALLOWED_HOSTS:\n    raise ValueError(\"destination denied\")",
        "JavaScript": f"const target = new URL({value});\nif (target.protocol !== \"https:\" || !ALLOWED_HOSTS.has(target.hostname)) throw new Error(\"destination denied\");",
        "TypeScript": f"const target = new URL({value});\nif (target.protocol !== \"https:\" || !ALLOWED_HOSTS.has(target.hostname)) throw new Error(\"destination denied\");",
        "PHP": f"$target = parse_url({value});\nif (($target['scheme'] ?? '') !== 'https' || !in_array($target['host'] ?? '', $allowedHosts, true)) {{ throw new RuntimeException('destination denied'); }}",
        "Java": f"URI target = URI.create({value});\nif (!\"https\".equals(target.getScheme()) || !allowedHosts.contains(target.getHost())) throw new SecurityException(\"destination denied\");",
        "C#": f"if (!Uri.TryCreate({value}, UriKind.Absolute, out var target) || target.Scheme != Uri.UriSchemeHttps || !allowedHosts.Contains(target.Host)) throw new InvalidOperationException();",
        "Go": f"target, err := url.Parse({value})\nif err != nil || target.Scheme != \"https\" || !allowedHosts[target.Hostname()] {{ return errDestinationDenied }}",
        "Ruby": f"target = URI.parse({value})\nraise \"destination denied\" unless target.scheme == \"https\" && ALLOWED_HOSTS.include?(target.host)",
    }
    suggested = patches.get(language)
    if suggested is None:
        return None
    return f"Parse `{value}` before `{_callee(evidence)}`. Compare normalized scheme and hostname with exact allowlist entries; resolve DNS and block private, loopback and link-local results.", suggested


def _deser_patch(language: str, value: str, evidence: str) -> tuple[str, str] | None:
    patches = {
        "Python": f"data = json.loads({value})\nvalidate_schema(data)",
        "JavaScript": f"const data = schema.parse(JSON.parse({value}));",
        "TypeScript": f"const data = schema.parse(JSON.parse({value}));",
        "PHP": f"$data = json_decode({value}, true, 32, JSON_THROW_ON_ERROR);",
        "Java": f"RequestDto data = objectMapper.readValue({value}, RequestDto.class);",
        "C#": f"var data = JsonSerializer.Deserialize<RequestDto>({value});",
        "Ruby": f"data = JSON.parse({value})",
    }
    suggested = patches.get(language)
    if suggested is None:
        return None
    return f"Replace `{_callee(evidence)}` with plain-data decoding of `{value}` into a fixed schema. Disable polymorphic type metadata.", suggested


def _code_patch(language: str, value: str, evidence: str) -> tuple[str, str] | None:
    patches = {
        "Python": f"data = ast.literal_eval({value})",
        "JavaScript": f"const data = schema.parse(JSON.parse({value}));",
        "TypeScript": f"const data = schema.parse(JSON.parse({value}));",
        "PHP": f"$data = json_decode({value}, true, 32, JSON_THROW_ON_ERROR);",
        "Java": f"RequestDto data = objectMapper.readValue({value}, RequestDto.class);",
        "C#": f"var data = JsonSerializer.Deserialize<RequestDto>({value});",
        "Ruby": f"data = JSON.parse({value})",
    }
    suggested = patches.get(language)
    if suggested is None:
        return None
    return f"Parse `{value}` as data and map operation names to fixed functions. Remove runtime evaluation through `{_callee(evidence)}`.", suggested


def _path_base(text: str) -> str | None:
    literals = re.findall(r'''["']((?:[A-Za-z]:[\\/]|/)[^"']*[\\/])[^"']*["']''', text)
    if not literals:
        return None
    return max(literals, key=len).replace("\\\\", "\\")


def _path_input(text: str) -> str | None:
    match = re.search(r'''["'](?:[A-Za-z]:[\\/]|/)[^"']*[\\/]["']\s*(?:\+|\.)\s*(\$?[A-Za-z_]\w*)''', text)
    return match.group(1) if match else None


def _callee(evidence: str) -> str:
    match = re.search(r"([A-Za-z_$][\w$:.>\-]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*\(", evidence)
    return re.sub(r"\s+", "", match.group(1)) if match else "the reported sink"


def _quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
