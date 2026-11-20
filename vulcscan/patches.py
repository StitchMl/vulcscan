"""Deterministic, finding-specific patch suggestions.

Each function rewrites one AST node into replacement source text, or returns
None when the rewrite cannot preserve the intended behavior. A suggestion is
``machine_applicable`` only when it replaces text on a single line and needs no
new import; ``--generate-diff`` emits nothing else.
"""

from __future__ import annotations

import ast
import re

from .models import Confidence, Remediation

_SHELL_METACHARACTERS = set("|&;<>()$`\\\"'*?[]#~=%{}!\n\r")
_VALUE_CONTEXT = re.compile(
    r"(?is)(?:[=<>,(]|\blike|\blimit|\boffset|\bthen|\bwhen|\bbetween|\band)\s*$"
)
_QMARK_DRIVERS = ("sqlite3", "aiosqlite")
_FORMAT_DRIVERS = ("psycopg2", "psycopg", "pymysql", "MySQLdb", "mysql.connector", "pgdb")


def python_suggestion(rule_id: str, node: ast.Call, text: str, imports: dict[str, str]) -> Remediation | None:
    if rule_id == "PY-DESER-001":
        return _yaml_safe_load(node, text)
    if rule_id == "PY-CMD-001":
        return _argument_list_command(node, text)
    if rule_id == "PY-SQL-001":
        return _parameterized_query(node, text, imports)
    if rule_id == "PY-CODE-001":
        return _literal_eval(node, text)
    return None


def structured_suggestion(rule_id: str, language: str, current: str) -> Remediation | None:
    """Return a review-only patch template when an exact rewrite needs type information."""
    if rule_id != "PHP-SQL-001" or language != "PHP":
        return None
    return Remediation(
        title="Replace the raw mysqli query with a prepared statement.",
        guidance="Substitute the real constant SQL, bind types and variables shown by the source-to-sink flow. Review the result before applying.",
        preferred=True,
        patch_confidence=Confidence.MEDIUM,
        patch_risk="MEDIUM",
        current=current,
        suggested=(
            '$stmt = $db->prepare("SELECT ... WHERE field = ?");\n'
            '$stmt->bind_param("s", $value);\n'
            '$stmt->execute();\n'
            '$result = $stmt->get_result();'
        ),
        machine_applicable=False,
    )


def keyword_suggestion(text: str, call: ast.Call, keyword: str, old: str, new: str) -> Remediation | None:
    for item in call.keywords:
        if item.arg != keyword or not isinstance(item.value, ast.Constant):
            continue
        segment = ast.get_source_segment(text, item)
        if not segment or "\n" in segment or not segment.rstrip().endswith(old):
            return None
        replacement = segment[: len(segment.rstrip()) - len(old)] + new
        return Remediation(
            title=f"Set {keyword}={new}.",
            guidance=f"Change {segment.strip()} to {replacement.strip()} in this call.",
            preferred=True,
            patch_confidence=Confidence.HIGH,
            patch_risk="LOW",
            current=segment,
            suggested=replacement,
            machine_applicable=True,
        )
    return None


def line_suggestion(text: str, node: ast.stmt, old: str, new: str) -> Remediation | None:
    segment = ast.get_source_segment(text, node)
    if not segment or "\n" in segment or not segment.rstrip().endswith(old):
        return None
    replacement = segment[: len(segment.rstrip()) - len(old)] + new
    return Remediation(
        title=f"Change the value to {new}.",
        guidance="Prefer reading the flag from deployment configuration that defaults to the safe value.",
        preferred=True,
        patch_confidence=Confidence.HIGH,
        patch_risk="LOW",
        current=segment,
        suggested=replacement,
        machine_applicable=True,
    )


def random_suggestion(text: str, call: ast.Call, name: str) -> Remediation | None:
    segment = ast.get_source_segment(text, call)
    if not segment:
        return None
    arguments = [ast.get_source_segment(text, item) or "" for item in call.args]
    short = name.rsplit(".", 1)[-1]
    replacement = _secrets_replacement(short, call, arguments)
    if replacement is None:
        return None
    return Remediation(
        title="Draw the value from the secrets module.",
        guidance="Add 'import secrets' and replace the call; secrets uses the operating system CSPRNG.",
        preferred=True,
        patch_confidence=Confidence.HIGH,
        patch_risk="LOW",
        current=segment,
        suggested=replacement,
        machine_applicable=False,
    )


_SECRETS_SINGLE_ARGUMENT = {
    "choice": "secrets.choice",
    "getrandbits": "secrets.randbits",
    "randrange": "secrets.randbelow",
}


def _secrets_replacement(short: str, call: ast.Call, arguments: list[str]) -> str | None:
    target = _SECRETS_SINGLE_ARGUMENT.get(short)
    if target is not None:
        return f"{target}({arguments[0]})" if len(arguments) == 1 and not call.keywords else None
    if short == "randint" and len(call.args) == 2 and all(
        isinstance(item, ast.Constant) and type(item.value) is int for item in call.args
    ):
        low, high = call.args[0].value, call.args[1].value
        if high >= low:
            return f"secrets.randbelow({high - low + 1})" + (f" + {low}" if low else "")
    return None


def _single_line(node: ast.AST) -> bool:
    return getattr(node, "lineno", 0) == getattr(node, "end_lineno", -1)


def _yaml_safe_load(node: ast.Call, text: str) -> Remediation | None:
    if not isinstance(node.func, ast.Attribute) or node.func.attr not in {"load", "load_all"} or not node.args:
        return None
    receiver = ast.get_source_segment(text, node.func.value)
    argument = ast.get_source_segment(text, node.args[0])
    segment = ast.get_source_segment(text, node)
    if not receiver or not argument or not segment:
        return None
    extra = [item for item in node.keywords if item.arg not in {"Loader", "loader"}]
    if extra or len(node.args) > 2:
        return None
    method = "safe_load" if node.func.attr == "load" else "safe_load_all"
    return Remediation(
        title=f"Use {receiver}.{method}.",
        guidance="safe_load builds only plain data types; documents with custom tags will fail to load.",
        preferred=True,
        patch_confidence=Confidence.HIGH,
        patch_risk="MEDIUM",
        current=segment,
        suggested=f"{receiver}.{method}({argument})",
        machine_applicable=_single_line(node),
    )


def _literal_eval(node: ast.Call, text: str) -> Remediation | None:
    if len(node.args) != 1 or node.keywords:
        return None
    argument = ast.get_source_segment(text, node.args[0])
    segment = ast.get_source_segment(text, node)
    if not argument or not segment:
        return None
    return Remediation(
        title="Parse literals with ast.literal_eval.",
        guidance="Valid only when the input is a Python literal (numbers, strings, lists, dicts); "
        "add 'import ast'. Expressions and calls will be rejected.",
        preferred=True,
        patch_confidence=Confidence.MEDIUM,
        patch_risk="MEDIUM",
        current=segment,
        suggested=f"ast.literal_eval({argument})",
        machine_applicable=False,
    )


def _joined_parts(node: ast.JoinedStr, text: str) -> list[tuple[str, str]] | None:
    parts: list[tuple[str, str]] = []
    for value in node.values:
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            parts.append(("lit", value.value))
        elif isinstance(value, ast.FormattedValue) and value.conversion == -1 and value.format_spec is None:
            source = ast.get_source_segment(text, value.value)
            if not source:
                return None
            parts.append(("expr", source))
        else:
            return None
    return parts


def _string_parts(node: ast.expr, text: str) -> list[tuple[str, str]] | None:
    """Flatten an f-string or '+' concatenation into ("lit", text)/("expr", source)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [("lit", node.value)]
    if isinstance(node, ast.JoinedStr):
        return _joined_parts(node, text)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _string_parts(node.left, text)
        right = _string_parts(node.right, text)
        if left is None or right is None:
            return None
        return left + right
    if isinstance(node, (ast.Name, ast.Attribute, ast.Subscript, ast.Call)):
        source = ast.get_source_segment(text, node)
        return [("expr", source)] if source else None
    return None


def _literal_tokens(value: str, state: dict) -> bool:
    """Tokenize literal text into state; False when the text cannot be split safely."""
    tokens: list[tuple[str, str]] = state["tokens"]
    for char in value:
        if char in _SHELL_METACHARACTERS:
            return False
        if char.isspace():
            if state["buffer"]:
                tokens.append(("lit", state["buffer"]))
                state["buffer"] = ""
            state["pending"] = False
        elif state["pending"]:
            return False
        else:
            state["buffer"] += char
    return True


def _command_tokens(parts: list[tuple[str, str]]) -> list[tuple[str, str]] | None:
    state: dict = {"tokens": [], "buffer": "", "pending": False}
    for kind, value in parts:
        if kind == "expr":
            if state["buffer"] or state["pending"]:
                return None  # value glued to other text: the shell would join them
            state["tokens"].append(("expr", value))
            state["pending"] = True
        elif not _literal_tokens(value, state):
            return None
    tokens: list[tuple[str, str]] = state["tokens"]
    if state["buffer"]:
        tokens.append(("lit", state["buffer"]))
    if not tokens or tokens[0][0] != "lit":
        return None
    return tokens


_REVIEW_ONLY_SHELL_COMMANDS = frozenset({
    "bash", "cd", "cmd", "command", "copy", "dash", "del", "dir",
    "echo", "eval", "exec", "exit", "export", "powershell", "pwsh",
    "read", "set", "sh", "source", "type", "zsh",
})


def _shell_rewrite_machine_applicable(node: ast.Call, tokens: list[tuple[str, str]]) -> bool:
    """Refuse automatic shell rewrites for builtins and interpreters."""
    return _single_line(node) and tokens[0][1].casefold() not in _REVIEW_ONLY_SHELL_COMMANDS


def _argument_list_command(node: ast.Call, text: str) -> Remediation | None:
    if not node.args:
        return None
    parts = _string_parts(node.args[0], text)
    if parts is None or not any(kind == "expr" for kind, _ in parts) or not any(kind == "lit" for kind, _ in parts):
        return None
    tokens = _command_tokens(parts)
    if tokens is None:
        return None
    argv = "[" + ", ".join(_py_string(value) if kind == "lit" else value for kind, value in tokens) + "]"
    function = ast.get_source_segment(text, node.func)
    segment = ast.get_source_segment(text, node)
    if not function or not segment:
        return None
    name = function.rsplit(".", 1)[-1]
    if name in {"run", "call", "check_call", "check_output", "Popen"}:
        if not any(item.arg == "shell" for item in node.keywords):
            return None
        rest = [ast.get_source_segment(text, item) for item in node.args[1:]]
        rest += [ast.get_source_segment(text, item) for item in node.keywords if item.arg != "shell"]
        if any(item is None for item in rest):
            return None
        suggested = f"{function}({', '.join([argv, *rest])})"
        applicable = _shell_rewrite_machine_applicable(node, tokens)
        confidence = Confidence.HIGH
    elif name == "system" and len(node.args) == 1:
        suggested = f"subprocess.run({argv}, check=False).returncode"
        applicable = False
        confidence = Confidence.MEDIUM
    else:
        return None
    return Remediation(
        title="Pass an argument list and drop the shell.",
        guidance="Each interpolated value becomes exactly one argument, so shell metacharacters lose their meaning. "
        "Values that start with '-' can still be read as options; validate them or end options with '--'.",
        preferred=True,
        patch_confidence=confidence,
        patch_risk="MEDIUM",
        current=segment,
        suggested=suggested,
        machine_applicable=applicable,
    )


def _placeholder(imports: dict[str, str]) -> str | None:
    targets = {target.split(".")[0] for target in imports.values()} | {
        ".".join(target.split(".")[:2]) for target in imports.values()
    }
    styles = set()
    if any(driver in targets for driver in _QMARK_DRIVERS):
        styles.add("?")
    if any(driver in targets for driver in _FORMAT_DRIVERS):
        styles.add("%s")
    return styles.pop() if len(styles) == 1 else None


def _percent_parts(node: ast.BinOp, text: str) -> list[tuple[str, str]] | None:
    values = node.right.elts if isinstance(node.right, ast.Tuple) else [node.right]
    sources = [ast.get_source_segment(text, item) for item in values]
    if any(item is None for item in sources):
        return None
    parts: list[tuple[str, str]] = []
    cursor = 0
    for piece in re.split(r"(%%|%[sdif])", node.left.value):
        if piece == "%%":
            parts.append(("lit", "%"))
        elif re.fullmatch(r"%[sdif]", piece):
            if cursor >= len(sources):
                return None
            parts.append(("expr", sources[cursor]))
            cursor += 1
        elif "%" in piece:
            return None
        else:
            parts.append(("lit", piece))
    return parts if cursor == len(sources) else None


def _format_parts(node: ast.Call, text: str) -> list[tuple[str, str]] | None:
    sources = [ast.get_source_segment(text, item) for item in node.args]
    if any(item is None for item in sources):
        return None
    parts: list[tuple[str, str]] = []
    cursor = 0
    for piece in re.split(r"(\{\})", node.func.value.value):
        if piece == "{}":
            if cursor >= len(sources):
                return None
            parts.append(("expr", sources[cursor]))
            cursor += 1
        elif "{" in piece or "}" in piece:
            return None
        else:
            parts.append(("lit", piece))
    return parts if cursor == len(sources) else None


def _is_percent_template(node: ast.expr) -> bool:
    return (
        isinstance(node, ast.BinOp)
        and isinstance(node.op, ast.Mod)
        and isinstance(node.left, ast.Constant)
        and isinstance(node.left.value, str)
    )


def _is_format_call(node: ast.expr) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
        and isinstance(node.func.value, ast.Constant)
        and isinstance(node.func.value.value, str)
        and not node.keywords
    )


def _sql_parts(node: ast.expr, text: str) -> list[tuple[str, str]] | None:
    if _is_percent_template(node):
        return _percent_parts(node, text)
    if _is_format_call(node):
        return _format_parts(node, text)
    if isinstance(node, (ast.JoinedStr, ast.BinOp)):
        return _string_parts(node, text)
    return None


def _unquote_placeholder(sql: str, parts: list[tuple[str, str]], index: int) -> str | None:
    """Drop the quote pair around a value; None when the context cannot take a bound value."""
    if sql.endswith(("'", '"')):
        following = parts[index + 1][1] if index + 1 < len(parts) and parts[index + 1][0] == "lit" else ""
        if not following.startswith(sql[-1]):
            return None
        if index + 1 < len(parts):
            parts[index + 1] = ("lit", following[1:])
        return sql[:-1]
    # identifier or keyword position: binding cannot replace it
    return sql if _VALUE_CONTEXT.search(sql) else None


def _bind_parts(parts: list[tuple[str, str]], placeholder: str) -> tuple[str, list[str]] | None:
    sql = ""
    values: list[str] = []
    for index, (kind, value) in enumerate(parts):
        if kind == "lit":
            sql += value
            continue
        unquoted = _unquote_placeholder(sql, parts, index)
        if unquoted is None or (placeholder == "%s" and "%" in unquoted):
            return None
        sql = unquoted + placeholder
        values.append(value)
    if placeholder == "%s" and "%" in sql.replace("%s", ""):
        return None
    return sql, values


def _parameterized_query(node: ast.Call, text: str, imports: dict[str, str]) -> Remediation | None:
    if len(node.args) != 1 or node.keywords or not isinstance(node.func, ast.Attribute):
        return None
    placeholder = _placeholder(imports)
    if placeholder is None:
        return None
    parts = _sql_parts(node.args[0], text)
    if parts is None or not any(kind == "expr" for kind, _ in parts):
        return None
    bound = _bind_parts(parts, placeholder)
    if bound is None:
        return None
    sql, values = bound
    function = ast.get_source_segment(text, node.func)
    segment = ast.get_source_segment(text, node)
    if not function or not segment:
        return None
    parameters = "(" + ", ".join(values) + ("," if len(values) == 1 else "") + ")"
    return Remediation(
        title="Bind the values as query parameters.",
        guidance=f"The driver imported by this module uses '{placeholder}' placeholders. "
        "The SQL text stays constant and the driver sends the values separately.",
        preferred=True,
        patch_confidence=Confidence.HIGH,
        patch_risk="LOW",
        current=segment,
        suggested=f"{function}({_py_string(sql)}, {parameters})",
        machine_applicable=_single_line(node),
    )


def _py_string(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r")
    return f'"{escaped}"'
