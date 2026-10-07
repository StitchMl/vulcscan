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
    r"(?is)(?:=|<|>|<=|>=|<>|!=|\blike|\bin\s*\(|,|\(|\bvalues\s*\(|\blimit|\boffset|\bthen|\bwhen|\bbetween|\band)\s*$"
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
    replacement: str | None = None
    short = name.rsplit(".", 1)[-1]
    if short == "choice" and len(arguments) == 1 and not call.keywords:
        replacement = f"secrets.choice({arguments[0]})"
    elif short == "getrandbits" and len(arguments) == 1 and not call.keywords:
        replacement = f"secrets.randbits({arguments[0]})"
    elif short == "randrange" and len(arguments) == 1 and not call.keywords:
        replacement = f"secrets.randbelow({arguments[0]})"
    elif short == "randint" and len(call.args) == 2 and all(
        isinstance(item, ast.Constant) and type(item.value) is int for item in call.args
    ):
        low, high = call.args[0].value, call.args[1].value
        if high >= low:
            replacement = f"secrets.randbelow({high - low + 1})" + (f" + {low}" if low else "")
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


def _string_parts(node: ast.expr, text: str) -> list[tuple[str, str]] | None:
    """Flatten an f-string or '+' concatenation into ("lit", text)/("expr", source)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [("lit", node.value)]
    if isinstance(node, ast.JoinedStr):
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


def _command_tokens(parts: list[tuple[str, str]]) -> list[tuple[str, str]] | None:
    tokens: list[tuple[str, str]] = []
    buffer = ""
    pending_expression = False
    for kind, value in parts:
        if kind == "expr":
            if buffer or pending_expression:
                return None  # value glued to other text: the shell would join them
            tokens.append(("expr", value))
            pending_expression = True
            continue
        for char in value:
            if char in _SHELL_METACHARACTERS:
                return None
            if char.isspace():
                if buffer:
                    tokens.append(("lit", buffer))
                    buffer = ""
                pending_expression = False
            else:
                if pending_expression:
                    return None
                buffer += char
    if buffer:
        tokens.append(("lit", buffer))
    if not tokens or tokens[0][0] != "lit":
        return None
    return tokens


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
        applicable = _single_line(node)
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


def _sql_parts(node: ast.expr, text: str) -> list[tuple[str, str]] | None:
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod) and isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
        values = node.right.elts if isinstance(node.right, ast.Tuple) else [node.right]
        sources = [ast.get_source_segment(text, item) for item in values]
        if any(item is None for item in sources):
            return None
        pieces = re.split(r"(%%|%[sdif])", node.left.value)
        parts: list[tuple[str, str]] = []
        cursor = 0
        for piece in pieces:
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
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
        and isinstance(node.func.value, ast.Constant)
        and isinstance(node.func.value.value, str)
        and not node.keywords
    ):
        sources = [ast.get_source_segment(text, item) for item in node.args]
        if any(item is None for item in sources):
            return None
        pieces = re.split(r"(\{\})", node.func.value.value)
        parts = []
        cursor = 0
        for piece in pieces:
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
    if isinstance(node, (ast.JoinedStr, ast.BinOp)):
        return _string_parts(node, text)
    return None


def _parameterized_query(node: ast.Call, text: str, imports: dict[str, str]) -> Remediation | None:
    if len(node.args) != 1 or node.keywords or not isinstance(node.func, ast.Attribute):
        return None
    placeholder = _placeholder(imports)
    if placeholder is None:
        return None
    parts = _sql_parts(node.args[0], text)
    if parts is None or not any(kind == "expr" for kind, _ in parts):
        return None
    sql = ""
    values: list[str] = []
    index = 0
    while index < len(parts):
        kind, value = parts[index]
        if kind == "lit":
            sql += value
            index += 1
            continue
        following = parts[index + 1][1] if index + 1 < len(parts) and parts[index + 1][0] == "lit" else ""
        if sql.endswith(("'", '"')):
            quote = sql[-1]
            if not following.startswith(quote):
                return None
            sql = sql[:-1]
            if index + 1 < len(parts):
                parts[index + 1] = ("lit", following[1:])
        elif not _VALUE_CONTEXT.search(sql):
            return None  # identifier or keyword position: binding cannot replace it
        if placeholder == "%s" and "%" in sql:
            return None
        sql += placeholder
        values.append(value)
        index += 1
    if placeholder == "%s" and "%" in sql.replace("%s", ""):
        return None
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
