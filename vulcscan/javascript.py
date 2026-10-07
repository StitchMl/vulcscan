"""JavaScript and TypeScript analysis.

A small statement parser splits the file into statements and blocks, tracks
lexical scopes (function, block, ``var`` hoisting to the function), resolves
module aliases for ``child_process``, ``fs`` and HTTP clients, and follows
values through declarations, assignments, destructuring, concatenation and
template literals. It is not a full ECMAScript parser: callbacks across files,
higher-order functions and dynamic property access are out of scope.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace

from .dataflow import (
    ALL_SINKS,
    CODE,
    COMMAND,
    ENVIRONMENT,
    FILESYSTEM,
    HTTP_REQUEST,
    LOCAL,
    NORMALIZED,
    NOT_CONSTANT,
    REDIRECT,
    REMOTE,
    SQL,
    SQL_KEYWORDS,
    UNKNOWN,
    Value,
    concatenate,
    constant,
    has_fixed_host,
    is_local_path,
    judge,
    merge,
    sanitize,
    source_value,
    unique_steps,
    with_step,
)
from .models import Confidence, Finding, FlowStep, Location
from .regex_safety import safe_for
from .rules import remediations_for, rule
from .source import JS_STYLE, LineIndex, blank_comments, code_mask, matching_paren, split_arguments

_KEYWORDS = {
    "break", "case", "catch", "class", "const", "continue", "debugger", "default", "delete", "do",
    "else", "export", "extends", "false", "finally", "for", "function", "if", "import", "in",
    "instanceof", "let", "new", "null", "of", "return", "super", "switch", "this", "throw", "true",
    "try", "typeof", "undefined", "var", "void", "while", "with", "yield", "async", "await", "static",
    "as", "from", "NaN", "Infinity", "interface", "type", "enum", "implements", "readonly",
    "string", "number", "boolean", "any", "unknown", "never", "object",
}
_REMOTE_SOURCE = re.compile(
    r"(?<![\w$.])(?:req|request|ctx(?:\.request)?)\s*\.\s*"
    r"(?:query|params|body|headers|cookies|signedCookies|files?|url|originalUrl|path|hostname)\b"
    r"|(?<![\w$.])req\s*\.\s*(?:get|header|param)\s*\("
)
_LOCAL_SOURCE = re.compile(r"(?<![\w$.])(?:process\s*\.\s*argv|Deno\s*\.\s*args|Bun\s*\.\s*argv)\b")
_ENV_SOURCE = re.compile(r"(?<![\w$.])(?:process\s*\.\s*env|Deno\s*\.\s*env)\b")
_IDENTIFIER = re.compile(r"(?<![\w$.])([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)")
_MODULES = {
    "child_process": "child_process",
    "fs": "fs",
    "fs/promises": "fs",
    "vm": "vm",
    "http": "http",
    "https": "http",
    "axios": "axios",
    "node-fetch": "fetch",
    "undici": "undici",
    "got": "got",
    "needle": "needle",
    "superagent": "superagent",
    "request": "request",
    "node-serialize": "node-serialize",
    "path": "path",
}
_REQUIRE = r"""require\(\s*['"](?:node:)?([\w@/.-]+)['"]\s*\)"""
_SANITIZER_CALLS: list[tuple[re.Pattern[str], frozenset[str]]] = [
    (re.compile(r"(?<![\w$.])(?:parseInt|parseFloat|Number|Math\s*\.\s*(?:floor|ceil|round|trunc|abs))\s*\("), ALL_SINKS),
    (re.compile(r"(?<![\w$.])Number\s*\.\s*(?:parseInt|parseFloat)\s*\("), ALL_SINKS),
    (re.compile(r"(?<![\w$])path\s*\.\s*basename\s*\("), frozenset({FILESYSTEM})),
    (re.compile(r"(?<![\w$])path\s*\.\s*(?:resolve|normalize|join)\s*\("), frozenset({NORMALIZED})),
    (re.compile(r"(?<![\w$.])encodeURIComponent\s*\("), frozenset({HTTP_REQUEST, REDIRECT})),
    (re.compile(r"(?<![\w$.])(?:shellescape|escapeShellArg|shellQuote\s*\.\s*quote)\s*\("), frozenset({COMMAND})),
    (re.compile(r"(?<![\w$.])(?:mysql|connection|conn|pool|SqlString|sqlstring)\s*\.\s*escape\s*\("), frozenset({SQL})),
]
_DB_RECEIVER = re.compile(r"(?i)(?:^|\.)(?:db|database|conn|connection|pool|client|knex|sequelize|mysql|pg|sql|prisma|trx|tx|tr|cursor)$")


@dataclass(slots=True)
class _Scope:
    function: bool
    name: str | None = None
    values: dict[str, Value] = field(default_factory=dict)
    allowlists: set[str] = field(default_factory=set)
    terminates: bool = False
    guard: list[tuple[str, frozenset[str]]] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class _Statement:
    start: int
    end: int
    opens: bool = False
    closes: bool = False


class _Analyzer:
    def __init__(self, path: str, text: str, language: str) -> None:
        self.path = path
        self.language = language
        self.text = blank_comments(text, JS_STYLE)
        self.mask = code_mask(text, JS_STYLE)
        self.index = LineIndex(text)
        self.scopes: list[_Scope] = [_Scope(function=True)]
        self.findings: list[Finding] = []
        self.objects: dict[str, str] = {}
        self.functions: dict[str, tuple[str, str]] = {}
        self._collect_imports()

    # Imports ----------------------------------------------------------------------

    def _collect_imports(self) -> None:
        text = self.text
        for match in re.finditer(rf"(?:const|let|var)\s+([\w$]+)\s*=\s*{_REQUIRE}(?:\s*\.\s*(promises))?", text):
            module = _MODULES.get(match.group(2))
            if module:
                self.objects[match.group(1)] = module
        for match in re.finditer(rf"(?:const|let|var)\s*\{{([^}}]*)\}}\s*=\s*{_REQUIRE}", text):
            self._named_imports(match.group(1), match.group(2), ":")
        for match in re.finditer(r"""import\s+(?:([\w$]+)\s*,?\s*)?(?:\*\s*as\s+([\w$]+)\s*)?(?:\{([^}]*)\}\s*)?from\s*['"](?:node:)?([\w@/.-]+)['"]""", text):
            default, namespace, named, source = match.groups()
            module = _MODULES.get(source)
            if not module:
                continue
            for alias in (default, namespace):
                if alias:
                    self.objects[alias] = module
            if named:
                self._named_imports(named, source, " as ")

    def _named_imports(self, names: str, source: str, separator: str) -> None:
        module = _MODULES.get(source)
        if not module:
            return
        for item in names.split(","):
            item = item.strip()
            if not item:
                continue
            exported, _, local = item.partition(separator)
            exported, local = exported.strip(), (local.strip() or exported.strip())
            if exported == "promises" and module == "fs":
                self.objects[local] = "fs"
            elif re.fullmatch(r"[\w$]+", local):
                self.functions[local] = (module, exported)

    # Statements -------------------------------------------------------------------

    def run(self) -> list[Finding]:
        statements = list(self._statements())
        for statement in statements:
            if statement.closes:
                self._close_block()
                continue
            self._statement(statement)
        return self.findings

    def _statements(self):
        mask = self.mask
        stack: list[tuple[str, int]] = []  # ("obj", 0) or ("block", saved paren depth)
        paren = 0
        start = 0
        length = len(mask)
        index = 0
        while index < length:
            char = mask[index]
            if char in "([":
                paren += 1
            elif char in ")]":
                paren = max(0, paren - 1)
            elif char == "{":
                if self._opens_block(start, index):
                    yield _Statement(start, index + 1, opens=True)
                    stack.append(("block", paren))
                    paren = 0
                    start = index + 1
                else:
                    stack.append(("obj", 0))
                    paren += 1
            elif char == "}":
                if stack and stack[-1][0] == "obj":
                    stack.pop()
                    paren = max(0, paren - 1)
                elif stack:
                    if mask[start:index].strip():
                        yield _Statement(start, index)
                    yield _Statement(index, index + 1, closes=True)
                    paren = stack.pop()[1]
                    start = index + 1
            elif char == ";" and paren == 0:
                if mask[start:index].strip():
                    yield _Statement(start, index + 1)
                start = index + 1
            elif char == "\n" and paren == 0 and self._complete(start, index):
                yield _Statement(start, index)
                start = index + 1
            index += 1
        if mask[start:].strip():
            yield _Statement(start, length)

    def _opens_block(self, start: int, brace: int) -> bool:
        header = self.mask[start:brace].rstrip()
        if not header:
            return True
        if header.endswith("=>") or header.endswith(")"):
            return True
        if re.search(r"(?:^|[^\w$])(?:else|try|finally|do)$", header):
            return True
        if re.search(r"\b(?:class|interface|enum|namespace)\b[^=(]*$", header):
            return True
        # function f(a): Type {  /  method(a): Promise<T> {
        if re.search(r"\)\s*:\s*[\w$<>\[\]|&., ]+$", header):
            return True
        return False

    def _complete(self, start: int, newline: int) -> bool:
        current = self.mask[start:newline].strip()
        if not current:
            return False
        if re.search(r"(?:[=+\-*/%&|^!~?:,(\[{.<>]|=>|\b(?:return|await|new|typeof|in|of|instanceof))$", current):
            return False
        following = self.mask[newline + 1 :].lstrip()
        return not re.match(r"(?:[.?:+\-*/%&|^,)\]=<>]|=>)", following)

    def _statement(self, statement: _Statement) -> None:
        start, end = statement.start, statement.end
        body_end = end - 1 if statement.opens else end
        code = self.mask[start:body_end]
        stripped = code.strip()
        scope = self.scopes[-1]
        if re.match(r"(?:return|throw)\b", stripped) or re.match(r"process\s*\.\s*exit\s*\(", stripped):
            scope.terminates = True
        self._sinks(start, body_end)
        new_scope: _Scope | None = None
        if statement.opens:
            new_scope = self._block_scope(start, body_end)
        self._assignment(start, body_end, new_scope)
        one_line_guard = re.match(r"if\s*\(", stripped) and not statement.opens
        if one_line_guard:
            self._one_line_guard(start, body_end)
        if new_scope is not None:
            self.scopes.append(new_scope)

    def _block_scope(self, start: int, end: int) -> _Scope:
        header = self.mask[start:end]
        function_match = (
            re.search(r"\bfunction\b\s*\*?\s*([\w$]*)\s*\(([^)]*)\)\s*(?::[^{]*)?$", header)
            or re.search(r"(?:([\w$]+)\s*[=:]\s*)?(?:async\s+)?\(([^()]*)\)\s*(?::[^=]*)?=>\s*$", header)
            or re.search(r"(?:([\w$]+)\s*[=:]\s*)?(?:async\s+)?([\w$]+)\s*=>\s*$", header)
        )
        method_match = re.match(
            r"\s*(?:(?:public|private|protected|static|async|get|set|readonly|override)\s+)*([\w$]+)\s*(?:<[^>]*>)?\s*\(([^)]*)\)\s*(?::[^{]*)?$",
            header,
        )
        if method_match and method_match.group(1) in {"if", "for", "while", "switch", "catch", "with"}:
            method_match = None
        if function_match or method_match:
            match = function_match or method_match
            assert match is not None
            name = match.group(1) or None
            scope = _Scope(function=True, name=name or self._enclosing_name())
            for parameter in _parameter_names(match.group(2)):
                scope.values[parameter] = UNKNOWN
            return scope
        scope = _Scope(function=False, name=self._enclosing_name())
        catch = re.search(r"\bcatch\s*\(\s*([\w$]+)", header)
        if catch:
            scope.values[catch.group(1)] = UNKNOWN
        loop = re.search(r"\bfor\s*\(\s*(?:const|let|var)\s+([\w$]+|\{[^}]*\}|\[[^\]]*\])\s+(?:of|in)\s+(.+)\)\s*$", header, re.DOTALL)
        if loop:
            offset = start + loop.start(2)
            iterable = self._value(offset, offset + len(loop.group(2)))
            for name in _pattern_names(loop.group(1)):
                scope.values[name] = iterable
        condition = re.match(r"\s*(?:else\s+)?if\s*\((.*)\)\s*$", header, re.DOTALL)
        if condition:
            offset = start + condition.start(1)
            when_true, when_false = self._condition(offset, offset + len(condition.group(1)))
            for name, categories in when_true:
                current = self._lookup(name)
                if current is not None:
                    scope.values[name] = sanitize(current, categories)
            scope.guard = when_false
        return scope

    def _close_block(self) -> None:
        if len(self.scopes) == 1:
            return
        closed = self.scopes.pop()
        if closed.guard and closed.terminates and not closed.function:
            self._apply_sanitization(closed.guard)

    def _one_line_guard(self, start: int, end: int) -> None:
        code = self.mask[start:end]
        match = re.match(r"\s*if\s*\(", code)
        if not match:
            return
        open_index = start + match.end() - 1
        close = matching_paren(self.mask, open_index)
        if close < 0 or close >= end:
            return
        rest = self.mask[close + 1 : end].strip()
        if not re.match(r"(?:return|throw)\b", rest) and not re.match(r"process\s*\.\s*exit\s*\(", rest):
            return
        _, when_false = self._condition(open_index + 1, close)
        self._apply_sanitization(when_false)

    def _apply_sanitization(self, items: list[tuple[str, frozenset[str]]]) -> None:
        for name, categories in items:
            for scope in reversed(self.scopes):
                if name in scope.values:
                    scope.values[name] = sanitize(scope.values[name], categories)
                    break

    def _enclosing_name(self) -> str | None:
        for scope in reversed(self.scopes):
            if scope.function and scope.name:
                return scope.name
        return None

    # Conditions -------------------------------------------------------------------

    def _condition(self, start: int, end: int) -> tuple[list[tuple[str, frozenset[str]]], list[tuple[str, frozenset[str]]]]:
        """Sanitizations implied when the condition is true and when it is false."""
        code = self.mask[start:end]
        stripped = code.strip()
        offset = start + (len(code) - len(code.lstrip()))
        if stripped.startswith("(") and matching_paren(self.mask, offset) == offset + len(stripped) - 1:
            return self._condition(offset + 1, offset + len(stripped) - 1)
        for operator in ("||", "&&"):
            parts = _split_top_level(self.mask, start, end, operator)
            if len(parts) > 1:
                results = [self._condition(a, b) for a, b in parts]
                if operator == "&&":
                    return [item for result in results for item in result[0]], []
                return [], [item for result in results for item in result[1]]
        if stripped.startswith("!") and not stripped.startswith("!="):
            when_true, when_false = self._condition(offset + 1, end)
            return when_false, when_true
        text = self.text[start:end]
        negative_index = re.search(r"\)\s*(?:===?\s*-1|<\s*0)\s*$", stripped)
        positive_index = re.search(r"\)\s*(?:!==?\s*-1|>=\s*0|>\s*-1)\s*$", stripped)
        membership = re.match(r"\s*(.+?)\s*\.\s*(?:includes|has|indexOf)\s*\(\s*([\w$.]+)\s*\)", text, re.DOTALL)
        if membership and self._is_allowlist(membership.group(1).strip()):
            items = [(membership.group(2), ALL_SINKS)]
            if ".indexOf" in text and negative_index:
                return [], items
            if ".indexOf" in text and not positive_index:
                return [], []
            return items, []
        regex = re.match(r"\s*/(.+)/([a-z]*)\s*\.\s*test\s*\(\s*([\w$.]+)\s*\)\s*$", text, re.DOTALL)
        if regex and "m" not in regex.group(2):
            categories = safe_for(regex.group(1), fullmatch=True) if regex.group(1).startswith("^") and regex.group(1).endswith("$") else frozenset()
            if categories:
                return [(regex.group(3), categories)], []
        startswith = re.match(r"\s*([\w$.]+)\s*\.\s*startsWith\s*\(", text)
        if startswith:
            current = self._lookup(startswith.group(1))
            if current is not None and NORMALIZED in current.sanitized:
                return [(startswith.group(1), frozenset({FILESYSTEM}))], []
        equality = re.match(r"""\s*([\w$.]+)\s*===?\s*(?:'[^']*'|"[^"]*")\s*$""", text) or re.match(
            r"""\s*(?:'[^']*'|"[^"]*")\s*===?\s*([\w$.]+)\s*$""", text
        )
        if equality:
            return [(equality.group(1), ALL_SINKS)], []
        numeric = re.match(r"\s*(?:Number\s*\.\s*(?:isInteger|isSafeInteger)|validator\s*\.\s*(?:isInt|isNumeric|isUUID|isAlphanumeric))\s*\(\s*([\w$.]+)\s*\)\s*$", text)
        if numeric:
            return [(numeric.group(1), ALL_SINKS)], []
        return [], []

    def _is_allowlist(self, expression: str) -> bool:
        if re.fullmatch(r"\[\s*(?:(?:'[^']*'|\"[^\"]*\"|\d+)\s*,?\s*)+\]", expression):
            return True
        return any(expression in scope.allowlists for scope in self.scopes)

    # Assignments ------------------------------------------------------------------

    def _assignment(self, start: int, end: int, new_scope: _Scope | None) -> None:
        code = self.mask[start:end]
        declaration = re.match(r"\s*(?:export\s+)?(const|let|var)\s+", code)
        if declaration:
            for target_start, target_end, value_start, value_end in self._declarators(start + declaration.end(), end):
                target = self.text[target_start:target_end].strip()
                value = self._declared_value(value_start, value_end, new_scope)
                self._bind_target(target, value, kind=declaration.group(1), statement=(start, end))
                if self._literal_allowlist(value_start, value_end) and re.fullmatch(r"[\w$]+", target):
                    self.scopes[-1].allowlists.add(target)
            return
        assignment = re.match(r"\s*([\w$]+(?:\s*\.\s*[\w$]+)*)\s*(\+?=)(?!=)", code)
        if assignment:
            value_start = start + assignment.end()
            value = self._declared_value(value_start, end, new_scope)
            name = re.sub(r"\s+", "", assignment.group(1))
            if assignment.group(2) == "+=":
                value = concatenate([self._lookup(name) or UNKNOWN, value])
            self._bind_target(name, value, kind=None, statement=(start, end))

    def _declared_value(self, value_start: int, value_end: int, new_scope: _Scope | None) -> Value:
        if new_scope is not None and new_scope.function:
            return Value()  # a function expression, not data
        if value_start >= value_end:
            return UNKNOWN
        return self._value(value_start, value_end)

    def _declarators(self, start: int, end: int) -> list[tuple[int, int, int, int]]:
        result = []
        for part_start, part_end in split_arguments(self.mask, start, end):
            part = self.mask[part_start:part_end]
            equals = _top_level_equals(part)
            if equals < 0:
                result.append((part_start, part_end, part_end, part_end))
                continue
            target_end = part_start + equals
            colon = _top_level_char(self.mask[part_start:target_end], ":")
            if colon >= 0 and not self.mask[part_start:target_end].lstrip().startswith(("{", "[")):
                target_end = part_start + colon  # TypeScript annotation
            value_end = part_end
            if self.mask[value_end - 1 : value_end] == ";":
                value_end -= 1
            result.append((part_start, target_end, part_start + equals + 1, value_end))
        return result

    def _bind_target(self, target: str, value: Value, *, kind: str | None, statement: tuple[int, int]) -> None:
        start, end = statement
        code = self.text[start:end]
        first = start + len(code) - len(code.lstrip())
        step = FlowStep("PROPAGATION", self._location(first, end), _compact(code), f"Value is assigned to {target}.")
        value = with_step(value, step)
        names = _pattern_names(target) if target[:1] in "{[" else [re.sub(r"\s+", "", target)]
        for name in names:
            if kind is None:
                self._assign(name, value)
            else:
                self._declare(name, value, function_scoped=kind == "var")

    def _declare(self, name: str, value: Value, *, function_scoped: bool) -> None:
        if function_scoped:
            for scope in reversed(self.scopes):
                if scope.function:
                    scope.values[name] = value
                    return
        self.scopes[-1].values[name] = value

    def _assign(self, name: str, value: Value) -> None:
        for scope in reversed(self.scopes):
            if name in scope.values:
                scope.values[name] = value
                return
        self.scopes[0].values[name] = value

    def _lookup(self, name: str) -> Value | None:
        for scope in reversed(self.scopes):
            if name in scope.values:
                return scope.values[name]
        return None

    def _literal_allowlist(self, start: int, end: int) -> bool:
        expression = self.text[start:end].strip().rstrip(";")
        return bool(
            re.fullmatch(
                r"(?:new\s+Set\s*\(\s*)?\[\s*(?:(?:'[^']*'|\"[^\"]*\"|\d+)\s*,?\s*)+\]\s*\)?(?:\s+as\s+const)?",
                expression,
            )
        )

    # Values -----------------------------------------------------------------------

    def _value(self, start: int, end: int) -> Value:
        text = self.text[start:end]
        mask = list(self.mask[start:end])
        stripped = text.strip().rstrip(";").strip()
        literal = re.fullmatch(r"""'((?:\\.|[^'\\])*)'|"((?:\\.|[^"\\])*)"|`((?:\\.|[^`\\$])*)`""", stripped, re.DOTALL)
        if literal:
            return constant(next(group for group in literal.groups() if group is not None))
        if re.fullmatch(r"-?\d+(?:\.\d+)?", stripped):
            return constant(stripped)
        values: list[Value] = []
        # Sanitizer calls: evaluate their arguments separately and hide them.
        joined = "".join(mask)
        for pattern, categories in _SANITIZER_CALLS:
            for match in pattern.finditer(joined):
                open_index = start + match.end() - 1
                close = matching_paren(self.mask, open_index)
                if close < 0 or close >= end:
                    continue
                inner = self._value(open_index + 1, close)
                values.append(sanitize(replace(inner, composed=False), categories))
                for position in range(match.start(), close - start + 1):
                    mask[position] = " "
            joined = "".join(mask)
        for pattern, trust, description in (
            (_REMOTE_SOURCE, REMOTE, "HTTP request input"),
            (_LOCAL_SOURCE, LOCAL, "Command-line argument"),
            (_ENV_SOURCE, ENVIRONMENT, "Environment variable"),
        ):
            for match in pattern.finditer(joined):
                absolute = start + match.start()
                step = FlowStep(
                    "SOURCE",
                    self._location(absolute, start + match.end()),
                    re.sub(r"\s+", "", self.text[absolute : start + match.end()]),
                    f"{description} from {re.sub(r'[\s(]+', '', match.group(0))}.",
                )
                values.append(source_value(step, trust))
                for position in range(match.start(), match.end()):
                    mask[position] = " "
            joined = "".join(mask)
        dynamic = False
        for match in _IDENTIFIER.finditer(joined):
            name = re.sub(r"\s+", "", match.group(1))
            if name.split(".")[0] in _KEYWORDS:
                continue
            following = joined[match.end() : match.end() + 2].lstrip()
            if following.startswith(":") and not following.startswith("::") and self._is_object_key(joined, match.start()):
                continue
            current = self._lookup(name)
            parts = name.split(".")
            while current is None and len(parts) > 1:
                parts = parts[:-1]
                current = self._lookup(".".join(parts))
            if current is not None:
                exact = len(parts) == len(name.split("."))
                values.append(current if exact else replace(current, literal=NOT_CONSTANT, prefix=None))
            else:
                dynamic = True
        merged = merge(*values) if values else Value()
        composed = _is_composed(stripped)
        prefix = _string_prefix(stripped)
        if prefix is None and len(values) == 1 and re.fullmatch(r"[\w$.\s]+", stripped):
            prefix = values[0].prefix
        result = replace(
            merged,
            dynamic=merged.dynamic or dynamic or merged.tainted,
            composed=composed and (merged.dynamic or dynamic or merged.tainted),
            prefix=prefix,
            text=" ".join(_string_contents(stripped))[:400] or merged.text,
        )
        if not (len(values) == 1 and re.fullmatch(r"[\w$.\s]+", stripped)):
            result = replace(result, literal=NOT_CONSTANT)
        return result

    @staticmethod
    def _is_object_key(mask: str, position: int) -> bool:
        before = mask[:position].rstrip()
        return before.endswith(("{", ","))

    # Sinks ------------------------------------------------------------------------

    def _sinks(self, start: int, end: int) -> None:
        code = self.mask[start:end]
        for match in re.finditer(r"(?<![\w$])((?:[\w$]+\s*\.\s*)*)([\w$]+)\s*\(", code):
            receiver = re.sub(r"\s+", "", match.group(1)).rstrip(".")
            if not receiver and code[: match.start()].rstrip().endswith("."):
                continue  # method call on an expression such as /re/.exec(x) or f().exec(x)
            open_index = start + match.end() - 1
            self._call(start + match.start(), open_index, receiver, match.group(2))
        for match in re.finditer(rf"{_REQUIRE}\s*\.\s*([\w$]+)\s*\(", self.text[start:end]):
            module = _MODULES.get(match.group(1))
            if module:
                self._dispatch(start + match.start(), start + match.end() - 1, module, match.group(2), "")

    def _call(self, call_start: int, open_index: int, receiver: str, method: str) -> None:
        if receiver:
            module = self.objects.get(receiver.split(".")[0])
            if module:
                self._dispatch(call_start, open_index, module, method, receiver)
                return
            self._generic_call(call_start, open_index, receiver, method)
            return
        if method in self.functions:
            module, exported = self.functions[method]
            self._dispatch(call_start, open_index, module, exported, "")
            return
        if method in self.objects:
            self._dispatch(call_start, open_index, self.objects[method], "__call__", "")
            return
        if method == "eval":
            self._emit_argument("JS-CODE-001", "eval", call_start, open_index, 0, unknown_origin=True)
        elif method == "Function":
            self._emit_argument("JS-CODE-001", "Function constructor", call_start, open_index, -1, unknown_origin=True)
        elif method in {"setTimeout", "setInterval"}:
            arguments = self._arguments(open_index)
            if arguments and self.mask[arguments[0][0]] in "'\"`":
                self._emit_argument("JS-CODE-001", f"{method} with string code", call_start, open_index, 0, unknown_origin=True)
        elif method == "fetch":
            self._emit_argument("JS-SSRF-001", "fetch", call_start, open_index, 0)

    def _dispatch(self, call_start: int, open_index: int, module: str, method: str, receiver: str) -> None:
        if module == "child_process":
            if method in {"exec", "execSync"}:
                self._emit_argument("JS-CMD-001", f"child_process.{method}", call_start, open_index, 0, unknown_origin=True)
            elif method in {"spawn", "spawnSync", "execFile", "execFileSync"}:
                arguments = self._arguments(open_index)
                options = " ".join(self.mask[a:b] for a, b in arguments[1:])
                if re.search(r"\bshell\s*:\s*true\b", options):
                    self._emit_argument("JS-CMD-001", f"child_process.{method}(shell: true)", call_start, open_index, 0, unknown_origin=True)
                else:
                    self._emit_argument("JS-CMD-001", f"child_process.{method} program path", call_start, open_index, 0)
        elif module == "fs" and re.fullmatch(
            r"(?:readFile|writeFile|appendFile|unlink|rm|rmdir|mkdir|readdir|open|copyFile|createReadStream|createWriteStream|readlink|symlink|chmod)(?:Sync)?",
            method,
        ):
            self._emit_argument("JS-PATH-001", f"fs.{method}", call_start, open_index, 0)
            if method.startswith("copyFile"):
                self._emit_argument("JS-PATH-001", f"fs.{method}", call_start, open_index, 1)
        elif module == "vm" and method in {"runInNewContext", "runInThisContext", "runInContext", "compileFunction", "Script"}:
            self._emit_argument("JS-CODE-001", f"vm.{method}", call_start, open_index, 0, unknown_origin=True)
        elif module in {"axios", "fetch", "got", "needle", "superagent", "request", "undici"} and method in {
            "__call__", "get", "post", "put", "patch", "delete", "head", "request", "default",
        }:
            self._emit_argument("JS-SSRF-001", f"{module} request", call_start, open_index, 0)
        elif module == "http" and method in {"get", "request"}:
            self._emit_argument("JS-SSRF-001", f"http.{method}", call_start, open_index, 0)
        elif module == "node-serialize" and method == "unserialize":
            self._emit_argument("JS-DESER-001", "node-serialize unserialize", call_start, open_index, 0)

    def _generic_call(self, call_start: int, open_index: int, receiver: str, method: str) -> None:
        last = receiver.split(".")[-1]
        if method in {"redirect", "location"} and last in {"res", "response", "reply", "ctx"}:
            index = -1 if method == "redirect" else 0
            self._emit_argument("OPEN-REDIRECT-001", f"{last}.{method}", call_start, open_index, index)
        elif method in {"sendFile", "download"} and last in {"res", "response"}:
            arguments = self._arguments(open_index)
            options = " ".join(self.mask[a:b] for a, b in arguments[1:])
            if not re.search(r"\broot\s*:", options):
                self._emit_argument("JS-PATH-001", f"res.{method}", call_start, open_index, 0)
        elif method in {"query", "execute", "raw", "$queryRawUnsafe", "$executeRawUnsafe", "unsafe"}:
            arguments = self._arguments(open_index)
            if not arguments:
                return
            value = self._value(*arguments[0])
            evidence = bool(SQL_KEYWORDS.search(value.text))
            database = bool(_DB_RECEIVER.search(receiver))
            if not evidence and not database:
                return
            certainty = Confidence.HIGH if evidence else Confidence.MEDIUM
            self._emit_value("JS-SQL-001", "database query", call_start, open_index, value, certainty, unknown_origin=True, sql_evidence=evidence)
        elif method == "unserialize" and last in {"serialize", "nodeSerialize", "node_serialize"}:
            self._emit_argument("JS-DESER-001", "node-serialize unserialize", call_start, open_index, 0)

    def _arguments(self, open_index: int) -> list[tuple[int, int]]:
        close = matching_paren(self.mask, open_index)
        if close < 0:
            return []
        return split_arguments(self.mask, open_index + 1, close)

    def _emit_argument(self, rule_id: str, sink: str, call_start: int, open_index: int, index: int, *, unknown_origin: bool = False) -> None:
        arguments = self._arguments(open_index)
        if not arguments:
            return
        try:
            span = arguments[index]
        except IndexError:
            return
        value = self._value(*span)
        if rule_id in {"JS-SSRF-001"} and has_fixed_host(value.prefix):
            return
        if rule_id == "OPEN-REDIRECT-001" and is_local_path(value.prefix):
            return
        self._emit_value(rule_id, sink, call_start, open_index, value, Confidence.HIGH, unknown_origin=unknown_origin)

    def _emit_value(
        self,
        rule_id: str,
        sink: str,
        call_start: int,
        open_index: int,
        value: Value,
        certainty: Confidence,
        *,
        unknown_origin: bool = False,
        sql_evidence: bool = True,
    ) -> None:
        definition = rule(rule_id)
        confidence = judge(definition.category, value, certainty=certainty, unknown_origin=unknown_origin, sql_evidence=sql_evidence)
        if confidence is None:
            return
        close = matching_paren(self.mask, open_index)
        end = close + 1 if close >= 0 else open_index + 1
        location = self._location(call_start, end)
        evidence = _compact(self.text[call_start:end])
        sink_step = FlowStep("SINK", location, evidence, f"Value reaches {sink}.")
        flow = list(unique_steps((*value.flow, sink_step)))
        source = next((step.location for step in flow if step.kind == "SOURCE"), None)
        reason = definition.explanation
        if source is None:
            reason += " The value is built at runtime from data whose origin the analyzer could not determine."
        elif value.trust == LOCAL:
            reason += " The source is a command-line argument."
        elif value.trust == ENVIRONMENT:
            reason += " The source is an environment variable, which an attacker rarely controls."
        self.findings.append(
            Finding(
                rule_id=rule_id,
                name=definition.name,
                cwe=definition.cwe,
                severity=definition.severity,
                confidence=confidence,
                category=definition.category,
                language=self.language,
                location=location,
                sink=sink,
                evidence=evidence,
                reason=reason,
                source=source,
                flow=flow,
                remediations=remediations_for(rule_id, evidence),
            )
        )

    def _location(self, start: int, end: int) -> Location:
        line, column = self.index.position(start)
        end_line, end_column = self.index.position(end)
        return Location(self.path, line, column, end_line, end_column, self._enclosing_name())


def analyze_javascript(relative_path: str, text: str, language: str) -> list[Finding]:
    return _Analyzer(relative_path, text, language).run()


def _parameter_names(text: str) -> list[str]:
    names: list[str] = []
    for part in _split_simple(text):
        part = part.strip()
        if not part:
            continue
        part = re.sub(r"^\.\.\.", "", part)
        if part.startswith(("{", "[")):
            names.extend(_pattern_names(part.split("=", 1)[0]))
            continue
        match = re.match(r"(?:(?:public|private|protected|readonly)\s+)*([\w$]+)", part)
        if match:
            names.append(match.group(1))
    return names


def _pattern_names(pattern: str) -> list[str]:
    """Names bound by a destructuring pattern such as ``{ a, b: c, ...rest }``."""
    pattern = pattern.strip()
    if not pattern.startswith(("{", "[")):
        name = re.match(r"[\w$]+", pattern)
        return [name.group(0)] if name else []
    inner = pattern[1:-1]
    names = []
    for item in _split_simple(inner):
        item = item.strip().split("=", 1)[0].strip()
        if not item:
            continue
        item = item.removeprefix("...")
        if ":" in item and pattern.startswith("{"):
            item = item.split(":", 1)[1].strip()
        names.extend(_pattern_names(item))
    return names


def _split_simple(text: str) -> list[str]:
    parts, depth, current = [], 0, ""
    for char in text:
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        if char == "," and depth == 0:
            parts.append(current)
            current = ""
        else:
            current += char
    parts.append(current)
    return parts


def _split_top_level(mask: str, start: int, end: int, operator: str) -> list[tuple[int, int]]:
    parts = []
    depth = 0
    segment = start
    index = start
    while index < end:
        char = mask[index]
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif depth == 0 and mask.startswith(operator, index):
            parts.append((segment, index))
            index += len(operator)
            segment = index
            continue
        index += 1
    parts.append((segment, end))
    return parts


def _top_level_equals(text: str) -> int:
    depth = 0
    for index, char in enumerate(text):
        if char in "([{<":
            depth += 1 if char != "<" else 0
        elif char in ")]}":
            depth -= 1
        elif char == "=" and depth == 0:
            following = text[index + 1 : index + 2]
            previous = text[index - 1 : index] if index else ""
            if following not in {"=", ">"} and previous not in {"=", "!", "<", ">"}:
                return index
    return -1


def _top_level_char(text: str, wanted: str) -> int:
    depth = 0
    for index, char in enumerate(text):
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == wanted and depth == 0:
            return index
    return -1


def _is_composed(expression: str) -> bool:
    if expression.startswith("`") and "${" in expression:
        return True
    without_strings = re.sub(r"""'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*"|`(?:\\.|[^`\\])*`""", "S", expression)
    return "+" in without_strings and ("S" in without_strings or "concat" in without_strings)


def _string_prefix(expression: str) -> str | None:
    template = re.match(r"`((?:\\.|[^`\\$])*)", expression)
    if template:
        return template.group(1)
    quoted = re.match(r"""(?:'((?:\\.|[^'\\])*)'|"((?:\\.|[^"\\])*)")\s*\+""", expression)
    if quoted:
        return quoted.group(1) if quoted.group(1) is not None else quoted.group(2)
    return None


def _string_contents(expression: str) -> list[str]:
    return [
        next(group for group in match.groups() if group is not None)
        for match in re.finditer(r"""'((?:\\.|[^'\\])*)'|"((?:\\.|[^"\\])*)"|`((?:\\.|[^`\\])*)`""", expression)
    ]


def _compact(value: str) -> str:
    return " ".join(value.strip().split())[:500]
