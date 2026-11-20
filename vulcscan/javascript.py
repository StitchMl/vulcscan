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
from dataclasses import dataclass, field

from .dataflow import (
    ALL_SINKS,
    COMMAND,
    ENVIRONMENT,
    FILESYSTEM,
    HTML_OUTPUT,
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
    replace_value,
    sanitize,
    source_value,
    unique_steps,
    with_step,
)
from .js_interproc import ImportedSink
from .models import Confidence, Finding, FlowStep, Location
from .regex_safety import safe_for
from .rules import remediations_for, rule
from .source import (
    JS_STYLE,
    LineIndex,
    blank_comments,
    code_mask,
    matching_paren,
    split_arguments,
)

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
    (re.compile(r"(?<![\w$.])(?:escapeHtml|htmlEscape)\s*\("), frozenset({HTML_OUTPUT})),
    (re.compile(r"(?<![\w$])(?:he|entities)\s*\.\s*encode\s*\("), frozenset({HTML_OUTPUT})),
]
_DB_RECEIVER = re.compile(r"(?i)(?:^|\.)(?:db|database|conn|connection|pool|client|knex|sequelize|mysql|pg|sql|prisma|trx|tx|tr|cursor)$")


_JS_NAME = r"[\w$]+"
_JS_LITERAL = r"""(?:'[^']*'|"[^"]*"|\d+)"""
_JS_ARRAY_LITERAL = r"\[\s*" + _JS_LITERAL + r"(?:\s*,\s*" + _JS_LITERAL + r")*(?:\s*,)?\s*\]"
_ALLOWLIST_LITERAL = re.compile(
    r"(?:new\s+Set\s*\(\s*)?" + _JS_ARRAY_LITERAL + r"(?:\s*\)(?:\s+as\s+const)?|\s+as\s+const|\s*)"
)
_ARRAY_LITERAL = re.compile(_JS_ARRAY_LITERAL)
_IMPORT_DEFAULT = r"(?:(" + _JS_NAME + r")(?:\s*,)?\s*)?"
_IMPORT_NAMESPACE = r"(?:\*\s*as\s+(" + _JS_NAME + r")\s*)?"
_IMPORT_NAMED = r"(?:\{([^}]*)\}\s*)?"
_IMPORT_SOURCE = r"""from\s*['"](?:node:)?([\w@/.-]+)['"]"""
_IMPORT_STATEMENT = re.compile(r"import\s+" + _IMPORT_DEFAULT + _IMPORT_NAMESPACE + _IMPORT_NAMED + _IMPORT_SOURCE)
_FUNCTION_DECLARATION = re.compile(r"\bfunction\b\s*+(?:\*\s*+)?([\w$]*+)\s*+\(([^)]*+)\)\s*+(?::[^{]*+)?$")
_ARROW_PARENS_CORE = re.compile(r"\(([^()]*+)\)\s*+(?::[^=]*+)?=>\s*+$")
_ARROW_BARE_CORE = re.compile(r"(?<![\w$])([\w$]++)\s*+=>\s*+$")
_METHOD_MODIFIERS = r"(?:(?:public|private|protected|static|async|get|set|readonly|override)\s+)*"
_METHOD_HEADER = re.compile(r"\s*" + _METHOD_MODIFIERS + r"([\w$]+)\s*(?:<[^>]*>\s*)?\(([^)]*)\)\s*(?::[^{]*)?$")
_CONTROL_KEYWORDS = {"if", "for", "while", "switch", "catch", "with"}
_CATCH_BINDING = re.compile(r"\bcatch\s*\(\s*([\w$]+)")
_FOR_BINDING = re.compile(
    r"\bfor\s*\(\s*(?:const|let|var)\s+(" + _JS_NAME + r"|\{[^}]*\}|\[[^\]]*\])\s+(?:of|in)\s+(\S.*)\)\s*$",
    re.DOTALL,
)
_IF_CONDITION = re.compile(r"\s*(?:else\s+)?if\s*\((.*)\)\s*$", re.DOTALL)
_TYPED_HEADER_TAIL = re.compile(r"\)\s*:\s*[\w$<>\[\]|&.,][\w$<>\[\]|&., ]*$")
_NEGATIVE_INDEX = re.compile(r"\)\s*(?:===?\s*-1|<\s*0)\s*$")
_POSITIVE_INDEX = re.compile(r"\)\s*(?:!==?\s*-1|>=\s*0|>\s*-1)\s*$")
_MEMBERSHIP = re.compile(r"\s*(\S.*?)\.\s*(?:includes|has|indexOf)\s*\(\s*([\w$.]+)\s*\)", re.DOTALL)
_REGEX_TEST = re.compile(r"\s*/(.+)/([a-z]*)\s*\.\s*test\s*\(\s*([\w$.]+)\s*\)\s*$", re.DOTALL)
_STARTS_WITH = re.compile(r"\s*([\w$.]+)\s*\.\s*startsWith\s*\(")
_STRING_LITERAL = r"""(?:'[^']*'|"[^"]*")"""
_EQUALITY_RIGHT = re.compile(r"\s*([\w$.]+)\s*===?\s*" + _STRING_LITERAL + r"\s*$")
_EQUALITY_LEFT = re.compile(r"\s*" + _STRING_LITERAL + r"\s*===?\s*([\w$.]+)\s*$")
_NUMERIC_VALIDATORS = (
    r"(?:Number\s*\.\s*(?:isInteger|isSafeInteger)"
    r"|validator\s*\.\s*(?:isInt|isNumeric|isUUID|isAlphanumeric))"
)
_NUMERIC_CHECK = re.compile(r"\s*" + _NUMERIC_VALIDATORS + r"\s*\(\s*([\w$.]+)\s*\)\s*$")
_Condition = tuple[list[tuple[str, frozenset[str]]], list[tuple[str, frozenset[str]]]]


_QUOTED_LITERAL = re.compile(r"""'((?:\\.|[^'\\])*)'|"((?:\\.|[^"\\])*)"|`((?:\\.|[^`\\$])*)`""", re.DOTALL)
_NUMBER_LITERAL = re.compile(r"-?\d+(?:\.\d+)?")
_PLAIN_REFERENCE = re.compile(r"[\w$.\s]+")
_SOURCE_PATTERNS = (
    (_REMOTE_SOURCE, REMOTE, "HTTP request input"),
    (_LOCAL_SOURCE, LOCAL, "Command-line argument"),
    (_ENV_SOURCE, ENVIRONMENT, "Environment variable"),
)
_FS_METHODS = re.compile(
    r"(?:readFile|writeFile|appendFile|unlink|rm|rmdir|mkdir|readdir|open|copyFile"
    r"|createReadStream|createWriteStream|readlink|symlink|chmod)(?:Sync)?"
)
_VM_METHODS = {"runInNewContext", "runInThisContext", "runInContext", "compileFunction", "Script"}
_HTTP_CLIENT_MODULES = {"axios", "fetch", "got", "needle", "superagent", "request", "undici"}
_HTTP_CLIENT_METHODS = {"__call__", "get", "post", "put", "patch", "delete", "head", "request", "default"}
_RESPONSE_OBJECTS = {"res", "response", "reply", "ctx"}
_REQUEST_OBJECT = re.compile(r"(?:[A-Za-z_$][\w$]*|(?:req|request)\s*\.\s*(?:body|query))")
_MONGO_METHODS = {"find", "findOne", "findOneAndUpdate", "updateOne", "deleteOne", "countDocuments"}
_MONGO_COLLECTION = re.compile(r"(?:users|accounts|orders|products)Collection", re.IGNORECASE)
_RAW_SQL_METHODS = {"raw", "literal", "$queryRawUnsafe", "$executeRawUnsafe", "unsafe"}
_SQL_METHODS = {"query", "execute"} | _RAW_SQL_METHODS


def _is_template_call(receiver: str, method: str) -> bool:
    return (
        (receiver in {"ejs", "pug"} and method in {"render", "compile"})
        or (receiver in {"Handlebars", "handlebars"} and method == "compile")
        or (receiver == "nunjucks" and method == "renderString")
    )


def _is_merge_call(receiver: str, method: str) -> bool:
    return (receiver == "Object" and method == "assign") or (
        receiver in {"_", "lodash"} and method in {"merge", "mergeWith", "defaultsDeep"}
    )


def _is_mongo_call(receiver: str, method: str) -> bool:
    return method in _MONGO_METHODS and (
        receiver in {"collection", "Model", "User", "Account"}
        or receiver.startswith(("db.collection", "mongoose.model"))
        or _MONGO_COLLECTION.fullmatch(receiver) is not None
    )



@dataclass(frozen=True, slots=True)
class _ArrowHeader:
    name: str | None
    parameters: str

    def group(self, index: int) -> str | None:
        return self.name if index == 1 else self.parameters


def _is_name_char(char: str) -> bool:
    return char.isalnum() or char in "_$"


def _arrow_name(header: str, core_start: int) -> str | None:
    """Name bound by ``name =``/``name:`` (optionally followed by ``async``) just before an arrow function."""
    end = core_start
    while end > 0 and header[end - 1].isspace():
        end -= 1
    if end < core_start and header.endswith("async", 0, end):
        end -= len("async")
        while end > 0 and header[end - 1].isspace():
            end -= 1
    if end == 0 or header[end - 1] not in "=:":
        return None
    end -= 1
    while end > 0 and header[end - 1].isspace():
        end -= 1
    start = end
    while start > 0 and _is_name_char(header[start - 1]):
        start -= 1
    return header[start:end] or None


def _arrow_header(header: str) -> _ArrowHeader | None:
    parens = _ARROW_PARENS_CORE.search(header)
    if parens is not None:
        return _ArrowHeader(_arrow_name(header, parens.start()), parens.group(1))
    bare = _ARROW_BARE_CORE.search(header)
    if bare is not None:
        return _ArrowHeader(_arrow_name(header, bare.start()), bare.group(1))
    return None


def _function_header(header: str) -> re.Match[str] | _ArrowHeader | None:
    function_match = _FUNCTION_DECLARATION.search(header) or _arrow_header(header)
    method_match = _METHOD_HEADER.match(header)
    if method_match and method_match.group(1) in _CONTROL_KEYWORDS:
        method_match = None
    return function_match or method_match


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


@dataclass(slots=True)
class _ScanState:
    stack: list[tuple[str, int]] = field(default_factory=list)  # ("obj", 0) or ("block", saved paren depth)
    paren: int = 0
    start: int = 0


class _Analyzer:
    def __init__(self, path: str, text: str, language: str, imported_sinks: dict[str, ImportedSink] | None = None) -> None:
        self.path = path
        self.language = language
        self.text = blank_comments(text, JS_STYLE)
        self.mask = code_mask(text, JS_STYLE)
        self.index = LineIndex(text)
        self.scopes: list[_Scope] = [_Scope(function=True)]
        self.findings: list[Finding] = []
        self.objects: dict[str, str] = {}
        self.functions: dict[str, tuple[str, str]] = {}
        self.imported_sinks = imported_sinks or {}
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
        for match in _IMPORT_STATEMENT.finditer(text):
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
            elif re.fullmatch(_JS_NAME, local):
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
        state = _ScanState()
        for index, char in enumerate(mask):
            if char in "([":
                state.paren += 1
            elif char in ")]":
                state.paren = max(0, state.paren - 1)
            elif char == "{":
                yield from self._open_brace(state, index)
            elif char == "}":
                yield from self._close_brace(state, index)
            elif char in ";\n" and state.paren == 0:
                yield from self._end_statement(state, index, char)
        if mask[state.start:].strip():
            yield _Statement(state.start, len(mask))

    def _open_brace(self, state: _ScanState, index: int):
        if self._opens_block(state.start, index):
            yield _Statement(state.start, index + 1, opens=True)
            state.stack.append(("block", state.paren))
            state.paren = 0
            state.start = index + 1
        else:
            state.stack.append(("obj", 0))
            state.paren += 1

    def _close_brace(self, state: _ScanState, index: int):
        if not state.stack:
            return
        if state.stack[-1][0] == "obj":
            state.stack.pop()
            state.paren = max(0, state.paren - 1)
            return
        if self.mask[state.start:index].strip():
            yield _Statement(state.start, index)
        yield _Statement(index, index + 1, closes=True)
        state.paren = state.stack.pop()[1]
        state.start = index + 1

    def _end_statement(self, state: _ScanState, index: int, char: str):
        if char == ";":
            if self.mask[state.start:index].strip():
                yield _Statement(state.start, index + 1)
            state.start = index + 1
        elif self._complete(state.start, index):
            yield _Statement(state.start, index)
            state.start = index + 1

    def _opens_block(self, start: int, brace: int) -> bool:
        header = self.mask[start:brace].rstrip()
        if not header:
            return True
        if header.endswith(("=>", ")")):
            return True
        if re.search(r"(?:^|[^\w$])(?:else|try|finally|do)$", header):
            return True
        if re.search(r"\b(?:class|interface|enum|namespace)\b[^=(]*$", header):
            return True
        # function f(a): Type {  /  method(a): Promise<T> {
        return bool(_TYPED_HEADER_TAIL.search(header))

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
        match = _function_header(header)
        if match is not None:
            name = match.group(1) or None
            scope = _Scope(function=True, name=name or self._enclosing_name())
            for parameter in _parameter_names(match.group(2)):
                scope.values[parameter] = UNKNOWN
            return scope
        scope = _Scope(function=False, name=self._enclosing_name())
        catch = _CATCH_BINDING.search(header)
        if catch:
            scope.values[catch.group(1)] = UNKNOWN
        self._bind_loop(scope, start, header)
        self._bind_condition(scope, start, header)
        return scope

    def _bind_loop(self, scope: _Scope, start: int, header: str) -> None:
        loop = _FOR_BINDING.search(header)
        if not loop:
            return
        offset = start + loop.start(2)
        iterable = self._value(offset, offset + len(loop.group(2)))
        for name in _pattern_names(loop.group(1)):
            scope.values[name] = iterable

    def _bind_condition(self, scope: _Scope, start: int, header: str) -> None:
        condition = _IF_CONDITION.match(header)
        if not condition:
            return
        offset = start + condition.start(1)
        when_true, when_false = self._condition(offset, offset + len(condition.group(1)))
        for name, categories in when_true:
            current = self._lookup(name)
            if current is not None:
                scope.values[name] = sanitize(current, categories)
        scope.guard = when_false

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

    def _condition(self, start: int, end: int) -> _Condition:
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
        result = self._membership_condition(text, stripped)
        if result is not None:
            return result
        for check in (
            self._regex_condition,
            self._starts_with_condition,
            self._equality_condition,
            self._numeric_condition,
        ):
            result = check(text)
            if result is not None:
                return result
        return [], []

    def _membership_condition(self, text: str, stripped: str) -> _Condition | None:
        membership = _MEMBERSHIP.match(text)
        if not (membership and self._is_allowlist(membership.group(1).strip())):
            return None
        items = [(membership.group(2), ALL_SINKS)]
        if ".indexOf" in text and _NEGATIVE_INDEX.search(stripped):
            return [], items
        if ".indexOf" in text and not _POSITIVE_INDEX.search(stripped):
            return [], []
        return items, []

    def _regex_condition(self, text: str) -> _Condition | None:
        regex = _REGEX_TEST.match(text)
        if not regex or "m" in regex.group(2):
            return None
        pattern = regex.group(1)
        categories = safe_for(pattern, fullmatch=True) if pattern.startswith("^") and pattern.endswith("$") else frozenset()
        if not categories:
            return None
        return [(regex.group(3), categories)], []

    def _starts_with_condition(self, text: str) -> _Condition | None:
        starts_with = _STARTS_WITH.match(text)
        if not starts_with:
            return None
        current = self._lookup(starts_with.group(1))
        if current is not None and NORMALIZED in current.sanitized:
            return [(starts_with.group(1), frozenset({FILESYSTEM}))], []
        return None

    def _equality_condition(self, text: str) -> _Condition | None:
        equality = _EQUALITY_RIGHT.match(text) or _EQUALITY_LEFT.match(text)
        if equality:
            return [(equality.group(1), ALL_SINKS)], []
        return None

    def _numeric_condition(self, text: str) -> _Condition | None:
        numeric = _NUMERIC_CHECK.match(text)
        if numeric:
            return [(numeric.group(1), ALL_SINKS)], []
        return None

    def _is_allowlist(self, expression: str) -> bool:
        if _ARRAY_LITERAL.fullmatch(expression):
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
                if self._literal_allowlist(value_start, value_end) and re.fullmatch(_JS_NAME, target):
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
        return bool(_ALLOWLIST_LITERAL.fullmatch(expression))

    # Values -----------------------------------------------------------------------

    def _value(self, start: int, end: int) -> Value:
        text = self.text[start:end]
        mask = list(self.mask[start:end])
        stripped = text.strip().rstrip(";").strip()
        literal = _QUOTED_LITERAL.fullmatch(stripped)
        if literal:
            return constant(next(group for group in literal.groups() if group is not None))
        if _NUMBER_LITERAL.fullmatch(stripped):
            return constant(stripped)
        values = self._sanitizer_values(start, end, mask)
        values.extend(self._source_values(start, mask))
        dynamic = self._identifier_values("".join(mask), values)
        merged = merge(*values) if values else Value()
        composed = _is_composed(stripped)
        direct = len(values) == 1 and _PLAIN_REFERENCE.fullmatch(stripped) is not None
        prefix = _string_prefix(stripped)
        if prefix is None and direct:
            prefix = values[0].prefix
        result = replace_value(
            merged,
            dynamic=merged.dynamic or dynamic or merged.tainted,
            composed=composed and (merged.dynamic or dynamic or merged.tainted),
            prefix=prefix,
            text=" ".join(_string_contents(stripped))[:400] or merged.text,
        )
        if not direct:
            result = replace_value(result, literal=NOT_CONSTANT)
        return result

    def _sanitizer_values(self, start: int, end: int, mask: list[str]) -> list[Value]:
        """Evaluate sanitizer-call arguments separately and hide the calls from ``mask``."""
        values: list[Value] = []
        joined = "".join(mask)
        for pattern, categories in _SANITIZER_CALLS:
            for match in pattern.finditer(joined):
                open_index = start + match.end() - 1
                close = matching_paren(self.mask, open_index)
                if close < 0 or close >= end:
                    continue
                inner = self._value(open_index + 1, close)
                values.append(sanitize(replace_value(inner, composed=False), categories))
                for position in range(match.start(), close - start + 1):
                    mask[position] = " "
            joined = "".join(mask)
        return values

    def _source_values(self, start: int, mask: list[str]) -> list[Value]:
        values: list[Value] = []
        joined = "".join(mask)
        for pattern, trust, description in _SOURCE_PATTERNS:
            for match in pattern.finditer(joined):
                absolute = start + match.start()
                origin = re.sub(r"[\s(]+", "", match.group(0))
                step = FlowStep(
                    "SOURCE",
                    self._location(absolute, start + match.end()),
                    re.sub(r"\s+", "", self.text[absolute : start + match.end()]),
                    f"{description} from {origin}.",
                )
                values.append(source_value(step, trust))
                for position in range(match.start(), match.end()):
                    mask[position] = " "
            joined = "".join(mask)
        return values

    def _identifier_values(self, joined: str, values: list[Value]) -> bool:
        """Append the values of known identifiers; return True when one is unknown."""
        dynamic = False
        for match in _IDENTIFIER.finditer(joined):
            name = re.sub(r"\s+", "", match.group(1))
            if name.split(".")[0] in _KEYWORDS:
                continue
            following = joined[match.end() : match.end() + 2].lstrip()
            if following.startswith(":") and not following.startswith("::") and self._is_object_key(joined, match.start()):
                continue
            current, exact = self._resolve_name(name)
            if current is None:
                dynamic = True
            else:
                values.append(current if exact else replace_value(current, literal=NOT_CONSTANT, prefix=None))
        return dynamic

    def _resolve_name(self, name: str) -> tuple[Value | None, bool]:
        """Look up a dotted name, falling back to its longest known prefix."""
        current = self._lookup(name)
        parts = name.split(".")
        while current is None and len(parts) > 1:
            parts = parts[:-1]
            current = self._lookup(".".join(parts))
        return current, len(parts) == len(name.split("."))

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
                self._dispatch(start + match.start(), start + match.end() - 1, module, match.group(2))

    def _call(self, call_start: int, open_index: int, receiver: str, method: str) -> None:
        if receiver:
            module = self.objects.get(receiver.split(".")[0])
            if module:
                self._dispatch(call_start, open_index, module, method)
                return
            self._generic_call(call_start, open_index, receiver, method)
            return
        if method in self.functions:
            module, exported = self.functions[method]
            self._dispatch(call_start, open_index, module, exported)
            return
        if method in self.objects:
            self._dispatch(call_start, open_index, self.objects[method], "__call__")
            return
        if method in self.imported_sinks:
            summary = self.imported_sinks[method]
            old_count = len(self.findings)
            self._emit_argument(
                summary.rule_id, "imported " + summary.sink,
                call_start, open_index, summary.parameter_index,
                unknown_origin=summary.rule_id in {"JS-CMD-001", "JS-CODE-001"},
            )
            if len(self.findings) > old_count:
                finding = self.findings[-1]
                sink_location = Location(summary.file, summary.line, function=None)
                finding.related_locations.append(sink_location)
                finding.flow.append(FlowStep(
                    "SINK", sink_location, summary.sink,
                    "Argument reaches a direct sink in an imported local function.",
                ))
                finding.confidence = Confidence.MEDIUM
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

    def _dispatch(self, call_start: int, open_index: int, module: str, method: str) -> None:
        if module == "child_process":
            self._child_process_call(call_start, open_index, method)
        elif module == "fs" and _FS_METHODS.fullmatch(method):
            self._emit_argument("JS-PATH-001", f"fs.{method}", call_start, open_index, 0)
            if method.startswith("copyFile"):
                self._emit_argument("JS-PATH-001", f"fs.{method}", call_start, open_index, 1)
        elif module == "vm" and method in _VM_METHODS:
            self._emit_argument("JS-CODE-001", f"vm.{method}", call_start, open_index, 0, unknown_origin=True)
        elif module in _HTTP_CLIENT_MODULES and method in _HTTP_CLIENT_METHODS:
            self._emit_argument("JS-SSRF-001", f"{module} request", call_start, open_index, 0)
        elif module == "http" and method in {"get", "request"}:
            self._emit_argument("JS-SSRF-001", f"http.{method}", call_start, open_index, 0)
        elif module == "node-serialize" and method == "unserialize":
            self._emit_argument("JS-DESER-001", "node-serialize unserialize", call_start, open_index, 0)

    def _child_process_call(self, call_start: int, open_index: int, method: str) -> None:
        if method in {"exec", "execSync"}:
            self._emit_argument("JS-CMD-001", f"child_process.{method}", call_start, open_index, 0, unknown_origin=True)
        elif method in {"spawn", "spawnSync", "execFile", "execFileSync"}:
            arguments = self._arguments(open_index)
            options = " ".join(self.mask[a:b] for a, b in arguments[1:])
            if re.search(r"\bshell\s*:\s*true\b", options):
                self._emit_argument("JS-CMD-001", f"child_process.{method}(shell: true)", call_start, open_index, 0, unknown_origin=True)
            else:
                self._emit_argument("JS-CMD-001", f"child_process.{method} program path", call_start, open_index, 0)

    def _generic_call(self, call_start: int, open_index: int, receiver: str, method: str) -> None:
        last = receiver.split(".")[-1]
        if self._response_call(call_start, open_index, last, method):
            return
        if _is_template_call(receiver, method):
            self._emit_argument(
                "JS-SSTI-001", f"{receiver}.{method} template source",
                call_start, open_index, 0,
            )
        elif _is_merge_call(receiver, method):
            arguments = self._arguments(open_index)
            if len(arguments) >= 2:
                self._emit_request_object("JS-PROTOTYPE-001", receiver, method, call_start, open_index, arguments[1])
        elif _is_mongo_call(receiver, method):
            arguments = self._arguments(open_index)
            if arguments:
                self._emit_request_object("JS-NOSQL-001", receiver, method, call_start, open_index, arguments[0])
        elif method in _SQL_METHODS:
            self._sql_call(call_start, open_index, receiver, method)
        elif method == "unserialize" and last in {"serialize", "nodeSerialize", "node_serialize"}:
            self._emit_argument("JS-DESER-001", "node-serialize unserialize", call_start, open_index, 0)

    def _response_call(self, call_start: int, open_index: int, last: str, method: str) -> bool:
        """Handle response-object sinks; return True when the call matched one."""
        if method in {"send", "write", "end", "html"} and last in _RESPONSE_OBJECTS:
            if not self._explicit_non_html_response(last, call_start):
                self._emit_argument("JS-XSS-001", f"{last}.{method}", call_start, open_index, 0)
        elif method in {"redirect", "location"} and last in _RESPONSE_OBJECTS:
            index = -1 if method == "redirect" else 0
            self._emit_argument("OPEN-REDIRECT-001", f"{last}.{method}", call_start, open_index, index)
        elif method in {"sendFile", "download"} and last in {"res", "response"}:
            arguments = self._arguments(open_index)
            options = " ".join(self.mask[a:b] for a, b in arguments[1:])
            if not re.search(r"\broot\s*:", options):
                self._emit_argument("JS-PATH-001", f"res.{method}", call_start, open_index, 0)
        else:
            return False
        return True

    def _emit_request_object(
        self, rule_id: str, receiver: str, method: str, call_start: int, open_index: int, span: tuple[int, int]
    ) -> None:
        """Report a request-controlled object passed whole to a merge or query call."""
        original = self.text[span[0]:span[1]].strip()
        if not _REQUEST_OBJECT.fullmatch(original):
            return
        value = self._value(*span)
        if value.trust != REMOTE or not value.sources:
            return
        self._emit_value(rule_id, receiver + "." + method, call_start, open_index, value, Confidence.MEDIUM)

    def _sql_call(self, call_start: int, open_index: int, receiver: str, method: str) -> None:
        arguments = self._arguments(open_index)
        if not arguments:
            return
        value = self._value(*arguments[0])
        raw_sql_api = method in _RAW_SQL_METHODS
        evidence = raw_sql_api or bool(SQL_KEYWORDS.search(value.text))
        database = bool(_DB_RECEIVER.search(receiver))
        if not evidence and not database:
            return
        certainty = Confidence.HIGH if evidence else Confidence.MEDIUM
        self._emit_value("JS-SQL-001", "database query", call_start, open_index, value, certainty, unknown_origin=True, sql_evidence=evidence)

    def _explicit_non_html_response(self, receiver: str, call_start: int) -> bool:
        context = self.text[max(0, call_start - 1600) : call_start]
        content_type = re.compile(
            rf"\b{re.escape(receiver)}\s*\.\s*(?:setHeader|header|type)\s*\(\s*"
            r"(?:['\"]Content-Type['\"]\s*,\s*)?['\"]"
            r"(?:application/json|application/octet-stream)(?:\s*;[^'\"]*)?['\"]\s*\)",
            re.IGNORECASE,
        )
        return bool(content_type.search(context))

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


def analyze_javascript(
    relative_path: str, text: str, language: str,
    imported_sinks: dict[str, ImportedSink] | None = None,
) -> list[Finding]:
    return _Analyzer(relative_path, text, language, imported_sinks).run()


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
        name = re.match(_JS_NAME, pattern)
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
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == "=" and depth == 0 and _is_plain_equals(text, index):
            return index
    return -1


def _is_plain_equals(text: str, index: int) -> bool:
    following = text[index + 1 : index + 2]
    previous = text[index - 1 : index] if index else ""
    return following not in {"=", ">"} and previous not in {"=", "!", "<", ">"}


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
