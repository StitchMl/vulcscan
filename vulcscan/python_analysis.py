"""Python analysis: AST-based taint tracking and AST pattern rules.

The engine parses every Python file of the repository, builds per-function
summaries (which parameters reach which sinks, what the function returns) and
resolves direct calls between project modules. It never imports or executes the
analyzed code.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field, replace

from . import patches
from .dataflow import (
    ALL_SINKS,
    CODE,
    COMMAND,
    DESERIALIZATION,
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
    TEMPLATE,
    UNKNOWN,
    XML,
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
    weakest,
    with_step,
)
from .models import Confidence, Finding, FlowStep, Location, ScanError
from .names import is_credential_name, is_random_sensitive_name, looks_like_secret, mentions_password
from .regex_safety import safe_for
from .rules import remediations_for, rule
from .source import split_lines, utf8_column_to_char

SUMMARY_ROUNDS = 4

_REQUEST_ATTRIBUTES = {
    "args": "query string",
    "form": "form body",
    "values": "query string or form body",
    "json": "JSON body",
    "data": "request body",
    "files": "uploaded file",
    "FILES": "uploaded file",
    "headers": "HTTP header",
    "cookies": "cookie",
    "COOKIES": "cookie",
    "GET": "query string",
    "POST": "form body",
    "body": "request body",
    "query_params": "query string",
    "path_params": "path parameter",
    "match_info": "path parameter",
    "stream": "request body",
    "META": "request metadata",
    "environ": "WSGI environment",
    "url": "request URL",
    "full_path": "request URL",
    "path": "request path",
    "query_string": "query string",
    "get_json": "JSON body",
    "get_data": "request body",
    "get_full_path": "request URL",
    "rel_url": "request URL",
    "post": "form body",
    "form_data": "form body",
}
_TORNADO_INPUT = {"get_argument", "get_arguments", "get_query_argument", "get_body_argument"}
_LOCAL_CALLS = {"input", "builtins.input", "sys.stdin.read", "sys.stdin.readline", "sys.stdin.readlines"}
_ENV_CALLS = {"os.getenv", "os.environ.get", "os.getenvb"}
_ROUTE_DECORATORS = {
    "route",
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "head",
    "options",
    "websocket",
    "api_route",
    "api_view",
}
_NON_INPUT_PARAMETERS = {"self", "cls", "request", "req", "response", "db", "session", "background_tasks"}
_SAFE_ANNOTATIONS = {"int", "float", "bool", "UUID", "uuid.UUID", "datetime", "date", "Decimal", "IPv4Address"}
_NON_INPUT_ANNOTATIONS = {"Request", "Response", "Session", "BackgroundTasks", "WebSocket", "HTTPConnection"}
_FASTAPI_INPUTS = {"Query", "Path", "Body", "Header", "Cookie", "Form", "File"}
_INJECTED = {"Depends", "Security"}

_SANITIZERS: dict[str, frozenset[str]] = {
    "int": ALL_SINKS,
    "float": ALL_SINKS,
    "bool": ALL_SINKS,
    "complex": ALL_SINKS,
    "len": ALL_SINKS,
    "hash": ALL_SINKS,
    "uuid.UUID": ALL_SINKS,
    "decimal.Decimal": ALL_SINKS,
    "ipaddress.ip_address": frozenset({COMMAND, SQL, CODE, FILESYSTEM, TEMPLATE, DESERIALIZATION}),
    "shlex.quote": frozenset({COMMAND}),
    "pipes.quote": frozenset({COMMAND}),
    "shlex.join": frozenset({COMMAND}),
    "os.path.basename": frozenset({FILESYSTEM}),
    "posixpath.basename": frozenset({FILESYSTEM}),
    "ntpath.basename": frozenset({FILESYSTEM}),
    "werkzeug.utils.secure_filename": frozenset({FILESYSTEM}),
    "werkzeug.secure_filename": frozenset({FILESYSTEM}),
    "werkzeug.utils.safe_join": frozenset({FILESYSTEM}),
    "werkzeug.security.safe_join": frozenset({FILESYSTEM}),
    "flask.safe_join": frozenset({FILESYSTEM}),
    "flask.helpers.safe_join": frozenset({FILESYSTEM}),
    "flask.url_for": frozenset({REDIRECT}),
    "django.urls.reverse": frozenset({REDIRECT}),
    "django.shortcuts.resolve_url": frozenset({REDIRECT}),
}
_NORMALIZERS = {
    "os.path.realpath",
    "os.path.abspath",
    "os.path.normpath",
    "posixpath.normpath",
    "ntpath.normpath",
}
_PATH_RETURNING_METHODS = {"resolve", "absolute", "expanduser", "joinpath", "with_name", "with_suffix", "with_stem"}
_PURE_FUNCTIONS = {
    "str",
    "repr",
    "format",
    "sorted",
    "list",
    "tuple",
    "set",
    "frozenset",
    "dict",
    "min",
    "max",
    "abs",
    "round",
    "pathlib.Path",
    "pathlib.PurePath",
    "pathlib.PurePosixPath",
    "pathlib.PureWindowsPath",
}
_STRING_METHODS = {
    "format",
    "join",
    "lower",
    "upper",
    "strip",
    "lstrip",
    "rstrip",
    "replace",
    "split",
    "rsplit",
    "encode",
    "decode",
    "title",
    "capitalize",
    "casefold",
    "zfill",
    "removeprefix",
    "removesuffix",
}
_ABORT_CALLS = {"abort", "flask.abort", "werkzeug.exceptions.abort", "sys.exit", "exit", "quit", "os._exit"}
_REDIRECT_GUARDS = {
    "url_has_allowed_host_and_scheme",
    "django.utils.http.url_has_allowed_host_and_scheme",
    "is_safe_url",
    "django.utils.http.is_safe_url",
}
_CHARACTER_PREDICATES = {"isdigit", "isdecimal", "isnumeric", "isalnum", "isalpha", "isidentifier"}

_SHELL_STRING_CALLS = {
    "os.system",
    "os.popen",
    "subprocess.getoutput",
    "subprocess.getstatusoutput",
    "commands.getoutput",
    "asyncio.create_subprocess_shell",
}
_SUBPROCESS_CALLS = {
    "subprocess.run",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.Popen",
}
_PROGRAM_CALLS = {"asyncio.create_subprocess_exec", "os.execv", "os.execvp", "os.execl", "os.execlp"}
_CODE_CALLS = {"eval", "exec", "builtins.eval", "builtins.exec"}
_PATH_CALLS = {
    "open",
    "builtins.open",
    "io.open",
    "codecs.open",
    "os.open",
    "os.remove",
    "os.unlink",
    "os.rmdir",
    "os.removedirs",
    "os.mkdir",
    "os.makedirs",
    "os.listdir",
    "os.scandir",
    "os.rename",
    "os.replace",
    "shutil.rmtree",
    "shutil.copy",
    "shutil.copy2",
    "shutil.copyfile",
    "shutil.copytree",
    "shutil.move",
    "flask.send_file",
    "aiofiles.open",
}
_TWO_PATH_CALLS = {"os.rename", "os.replace", "shutil.copy", "shutil.copy2", "shutil.copyfile", "shutil.copytree", "shutil.move"}
_PATH_METHODS_ANY_RECEIVER = {"read_text", "read_bytes", "write_text", "write_bytes"}
_PATH_METHODS_PATHLIB = {"open", "unlink", "rmdir", "mkdir", "touch", "iterdir", "rename", "replace"}
_DESERIALIZERS = {
    "pickle.load",
    "pickle.loads",
    "pickle.Unpickler",
    "_pickle.load",
    "_pickle.loads",
    "cPickle.load",
    "cPickle.loads",
    "dill.load",
    "dill.loads",
    "marshal.load",
    "marshal.loads",
    "shelve.open",
    "joblib.load",
    "jsonpickle.decode",
    "pandas.read_pickle",
    "yaml.unsafe_load",
    "yaml.unsafe_load_all",
}
_SAFE_YAML_LOADERS = ("SafeLoader", "CSafeLoader", "BaseLoader", "CBaseLoader", "FullLoader", "CFullLoader")
_HTTP_FUNCTIONS = {
    "requests.get": 0,
    "requests.post": 0,
    "requests.put": 0,
    "requests.patch": 0,
    "requests.delete": 0,
    "requests.head": 0,
    "requests.options": 0,
    "requests.request": 1,
    "httpx.get": 0,
    "httpx.post": 0,
    "httpx.put": 0,
    "httpx.patch": 0,
    "httpx.delete": 0,
    "httpx.head": 0,
    "httpx.options": 0,
    "httpx.request": 1,
    "httpx.stream": 1,
    "urllib.request.urlopen": 0,
    "urllib.request.Request": 0,
    "urllib3.request": 1,
    "aiohttp.request": 1,
}
_HTTP_CLIENT_ORIGINS = {
    "requests.Session",
    "requests.session",
    "requests.sessions.Session",
    "httpx.Client",
    "httpx.AsyncClient",
    "aiohttp.ClientSession",
    "urllib3.PoolManager",
}
_HTTP_CLIENT_METHODS = {
    "get": 0,
    "post": 0,
    "put": 0,
    "patch": 0,
    "delete": 0,
    "head": 0,
    "options": 0,
    "request": 1,
    "stream": 1,
    "urlopen": 1,
}
_TEMPLATE_CALLS = {
    "flask.render_template_string",
    "jinja2.Template",
    "jinja2.environment.Template",
    "mako.template.Template",
    "django.template.Template",
    "tornado.template.Template",
}
_REDIRECT_CALLS = {
    "flask.redirect",
    "werkzeug.utils.redirect",
    "django.shortcuts.redirect",
    "django.http.HttpResponseRedirect",
    "django.http.HttpResponsePermanentRedirect",
    "django.http.response.HttpResponseRedirect",
    "starlette.responses.RedirectResponse",
    "fastapi.responses.RedirectResponse",
}
_LXML_PARSE = {"lxml.etree.fromstring", "lxml.etree.XML", "lxml.etree.parse"}
_DB_RECEIVER = re.compile(r"(?i)(?:^|[._])(?:cursor|cur|conn|connection|db|database|session|engine|sqlite\w*|pg|mysql|psycopg\w*)$")


@dataclass(slots=True)
class FunctionInfo:
    qualname: str
    node: ast.FunctionDef | ast.AsyncFunctionDef
    class_name: str | None
    receives_instance: bool
    params: tuple[str, ...]
    kwonly: tuple[str, ...]


@dataclass(slots=True)
class Module:
    relative: str
    text: str
    tree: ast.Module
    lines: list[str]
    name: str
    package: str
    imports: dict[str, str] = field(default_factory=dict)
    functions: dict[str, FunctionInfo] = field(default_factory=dict)
    classes: set[str] = field(default_factory=set)
    constants: dict[str, Value] = field(default_factory=dict)


@dataclass(slots=True)
class SinkTemplate:
    rule_id: str
    module: Module
    node: ast.Call
    sink: str
    value: Value
    certainty: Confidence
    function: str | None
    sql_evidence: bool


@dataclass(slots=True)
class Summary:
    returned: Value | None = None
    sinks: list[SinkTemplate] = field(default_factory=list)


def analyze_python(relative_path: str, text: str) -> tuple[list[Finding], str | None]:
    """Analyze a single file. Kept for callers that do not need project scope."""
    project = PythonProject([(relative_path, text)])
    findings = project.analyze()
    error = project.errors[0].message if project.errors else None
    return findings, error


class PythonProject:
    def __init__(self, sources: Iterable[tuple[str, str]]) -> None:
        self.modules: list[Module] = []
        self.errors: list[ScanError] = []
        self.summaries: dict[tuple[str, str], Summary] = {}
        self._by_name: dict[str, list[Module]] = {}
        for relative, text in sorted(sources, key=lambda item: item[0].casefold()):
            try:
                tree = ast.parse(text, filename=relative)
            except (SyntaxError, ValueError, RecursionError, MemoryError) as exc:
                self.errors.append(ScanError(relative, "python-parse", f"{exc.__class__.__name__}: {exc}"))
                continue
            name, package = _module_name(relative)
            module = Module(relative, text, tree, split_lines(text), name, package)
            _collect_symbols(module)
            self.modules.append(module)
            self._by_name.setdefault(name, []).append(module)

    def analyze(self) -> list[Finding]:
        findings: list[Finding] = []
        for module in self.modules:
            self._run_guarded(module, lambda module=module: self._collect_constants(module))
        for _ in range(SUMMARY_ROUNDS):
            for module in self.modules:
                for qualname in sorted(module.functions):
                    self._run_guarded(
                        module, lambda module=module, qualname=qualname: self._summarize(module, qualname)
                    )
        for module in self.modules:
            def emit(module: Module = module) -> None:
                module_findings: list[Finding] = []
                walker = _Walker(self, module, None, module_findings)
                walker.run(_module_statements(module.tree), dict(module.constants))
                for qualname in sorted(module.functions):
                    info = module.functions[qualname]
                    walker = _Walker(self, module, info, module_findings)
                    walker.run(info.node.body, self._entry_environment(module, info))
                module_findings.extend(_pattern_findings(module))
                findings.extend(module_findings)

            self._run_guarded(module, emit)
        return findings

    def _run_guarded(self, module: Module, action) -> None:
        try:
            action()
        except Exception as exc:  # noqa: BLE001 - one module must not stop the others; the error is reported
            self.errors.append(ScanError(module.relative, "python-analysis", f"{exc.__class__.__name__}: {exc}"))

    def _collect_constants(self, module: Module) -> None:
        counts: dict[str, int] = {}
        declared_global: set[str] = set()
        for node in ast.walk(module.tree):
            if isinstance(node, ast.Global):
                declared_global.update(node.names)
        for statement in _module_statements(module.tree):
            for target in _assigned_names(statement):
                counts[target] = counts.get(target, 0) + 1
        walker = _Walker(self, module, None, None)
        environment: dict[str, Value] = {}
        for statement in _module_statements(module.tree):
            if not isinstance(statement, (ast.Assign, ast.AnnAssign)) or statement.value is None:
                continue
            targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
            if len(targets) != 1 or not isinstance(targets[0], ast.Name):
                continue
            name = targets[0].id
            if counts.get(name) != 1 or name in declared_global:
                continue
            value = walker.expression(statement.value, environment)
            if not value.tainted:
                environment[name] = value
        module.constants = environment

    def _summarize(self, module: Module, qualname: str) -> None:
        info = module.functions[qualname]
        summary = Summary()
        environment = dict(module.constants)
        for index, name in enumerate((*info.params, *info.kwonly)):
            environment[name] = Value(dynamic=True, params=frozenset({index}))
        walker = _Walker(self, module, info, None, summary)
        walker.run(info.node.body, environment)
        self.summaries[(module.relative, qualname)] = summary

    def _entry_environment(self, module: Module, info: FunctionInfo) -> dict[str, Value]:
        environment = dict(module.constants)
        for name in (*info.params, *info.kwonly):
            environment[name] = UNKNOWN
        for argument, sanitized in _route_inputs(info.node, module):
            location = _location(module, argument, info.qualname)
            step = FlowStep("SOURCE", location, argument.arg, "HTTP route parameter enters the handler.")
            value = source_value(step, REMOTE)
            environment[argument.arg] = sanitize(value, ALL_SINKS) if sanitized else value
        return environment

    def resolve(self, module: Module, function: FunctionInfo | None, func: ast.expr) -> tuple[Module, FunctionInfo, bool] | None:
        """Resolve a call target to a project function.

        Returns (module, function, bound) where ``bound`` means the call passes
        the receiver as the first argument (``self.method()``).
        """
        if isinstance(func, ast.Name):
            if function is not None:
                nested = module.functions.get(f"{function.qualname}.{func.id}")
                if nested is not None:
                    return module, nested, False
            local = module.functions.get(func.id)
            if local is not None and local.class_name is None:
                return module, local, False
            target = module.imports.get(func.id)
            return self._resolve_dotted(target, bound=False) if target else None
        if not isinstance(func, ast.Attribute):
            return None
        base = func.value
        if isinstance(base, ast.Name):
            if base.id in {"self", "cls"} and function is not None and function.class_name:
                method = module.functions.get(f"{function.class_name}.{func.attr}")
                if method is not None:
                    return module, method, method.receives_instance
                return None
            if base.id in module.classes:
                method = module.functions.get(f"{base.id}.{func.attr}")
                return (module, method, False) if method is not None else None
            target = module.imports.get(base.id)
            if target:
                return self._resolve_dotted(f"{target}.{func.attr}", bound=False)
        return None

    def _resolve_dotted(self, dotted: str, *, bound: bool) -> tuple[Module, FunctionInfo, bool] | None:
        module_name, _, attribute = dotted.rpartition(".")
        if not module_name:
            return None
        candidates = self._modules_named(module_name)
        if len(candidates) != 1:
            return None
        info = candidates[0].functions.get(attribute)
        if info is None or info.class_name is not None:
            return None
        return candidates[0], info, bound

    def _modules_named(self, dotted: str) -> list[Module]:
        exact = self._by_name.get(dotted)
        if exact:
            return exact
        suffix = "." + dotted
        return [module for name, items in self._by_name.items() if name.endswith(suffix) for module in items]


class _Walker:
    """Abstract interpretation of one statement list.

    With ``summary`` set, it records which parameters reach sinks. With
    ``findings`` set, it reports findings. With neither, it only evaluates.
    """

    def __init__(
        self,
        project: PythonProject,
        module: Module,
        function: FunctionInfo | None,
        findings: list[Finding] | None,
        summary: Summary | None = None,
    ) -> None:
        self.project = project
        self.module = module
        self.function = function
        self.findings = findings
        self.summary = summary
        self.function_name = function.qualname if function else None

    # Statements -----------------------------------------------------------------

    def run(self, statements: Sequence[ast.stmt], environment: dict[str, Value]) -> dict[str, Value]:
        env = dict(environment)
        for statement in statements:
            env = self.statement(statement, env)
        return env

    def statement(self, statement: ast.stmt, env: dict[str, Value]) -> dict[str, Value]:
        if isinstance(statement, ast.Assign):
            value = self.expression(statement.value, env)
            for target in statement.targets:
                self.bind(target, self._assigned(value, statement), env)
        elif isinstance(statement, ast.AnnAssign):
            if statement.value is not None:
                value = self.expression(statement.value, env)
                self.bind(statement.target, self._assigned(value, statement), env)
        elif isinstance(statement, ast.AugAssign):
            current = self.expression(statement.target, env)
            added = self.expression(statement.value, env)
            combined = concatenate([current, added]) if isinstance(statement.op, (ast.Add, ast.Mod)) else merge(current, added)
            self.bind(statement.target, self._assigned(combined, statement), env)
        elif isinstance(statement, ast.Expr):
            self.expression(statement.value, env)
            self._apply_raising_check(statement.value, env)
        elif isinstance(statement, ast.Return):
            value = self.expression(statement.value, env) if statement.value else Value()
            if self.summary is not None:
                previous = self.summary.returned
                self.summary.returned = value if previous is None else merge(previous, value)
        elif isinstance(statement, ast.If):
            env = self._if(statement, env)
        elif isinstance(statement, (ast.For, ast.AsyncFor)):
            iterable = self.expression(statement.iter, env)
            loop_env = dict(env)
            for _ in range(2):
                self.bind(statement.target, iterable, loop_env)
                body_env = self.run(statement.body, loop_env)
                loop_env = _merge_environments(loop_env, body_env)
            env = self.run(statement.orelse, _merge_environments(env, loop_env))
        elif isinstance(statement, ast.While):
            self.expression(statement.test, env)
            loop_env = dict(env)
            for _ in range(2):
                loop_env = _merge_environments(loop_env, self.run(statement.body, loop_env))
            env = self.run(statement.orelse, _merge_environments(env, loop_env))
        elif isinstance(statement, (ast.With, ast.AsyncWith)):
            for item in statement.items:
                value = self.expression(item.context_expr, env)
                if item.optional_vars is not None:
                    self.bind(item.optional_vars, value, env)
            env = self.run(statement.body, env)
        elif isinstance(statement, (ast.Try, getattr(ast, "TryStar", ast.Try))):
            body_env = self.run(statement.body, env)
            handler_start = _merge_environments(env, body_env)
            outcomes = [] if _terminates(statement.body) else [self.run(statement.orelse, body_env)]
            for handler in statement.handlers:
                handler_env = dict(handler_start)
                if handler.name:
                    handler_env[handler.name] = UNKNOWN
                result = self.run(handler.body, handler_env)
                if not _terminates(handler.body):
                    outcomes.append(result)
            env = _merge_all(outcomes) if outcomes else handler_start
            env = self.run(statement.finalbody, env)
        elif isinstance(statement, ast.Match):
            subject = self.expression(statement.subject, env)
            outcomes = []
            for case in statement.cases:
                case_env = dict(env)
                for name in _pattern_names(case.pattern):
                    case_env[name] = subject
                result = self.run(case.body, case_env)
                if not _terminates(case.body):
                    outcomes.append(result)
            env = _merge_all([env, *outcomes])
        elif isinstance(statement, ast.Delete):
            for target in statement.targets:
                if isinstance(target, ast.Name):
                    env.pop(target.id, None)
        elif isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            env.pop(statement.name, None)
        elif isinstance(statement, (ast.Import, ast.ImportFrom)):
            for alias in statement.names:
                env.pop((alias.asname or alias.name).split(".")[0], None)
        else:
            for child in ast.iter_child_nodes(statement):
                if isinstance(child, ast.expr):
                    self.expression(child, env)
        return env

    def _if(self, statement: ast.If, env: dict[str, Value]) -> dict[str, Value]:
        self.expression(statement.test, env)
        when_true, when_false = self._guard(statement.test, env)
        body_env = self._apply_guard(dict(env), when_true)
        else_env = self._apply_guard(dict(env), when_false)
        body_result = self.run(statement.body, body_env)
        else_result = self.run(statement.orelse, else_env)
        outcomes = []
        if not _terminates(statement.body):
            outcomes.append(body_result)
        if not _terminates(statement.orelse):
            outcomes.append(else_result)
        return _merge_all(outcomes) if outcomes else _merge_environments(body_result, else_result)

    def _assigned(self, value: Value, node: ast.AST) -> Value:
        step = FlowStep("PROPAGATION", self.location(node), self.code(node), "Value is assigned.")
        return with_step(value, step)

    def bind(self, target: ast.AST, value: Value, env: dict[str, Value]) -> None:
        if isinstance(target, ast.Name):
            env[target.id] = value
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self.bind(element.value if isinstance(element, ast.Starred) else element, value, env)
        elif isinstance(target, ast.Attribute):
            key = _strict_dotted(target)
            if key:
                env[key] = value
        elif isinstance(target, ast.Subscript):
            key = _strict_dotted(target.value)
            if key:
                env[key] = merge(env.get(key, UNKNOWN), value)

    # Guards ---------------------------------------------------------------------

    def _guard(self, test: ast.expr, env: dict[str, Value]) -> tuple[list[tuple[str, frozenset[str]]], list[tuple[str, frozenset[str]]]]:
        """Return sanitizations implied when ``test`` is true and when it is false."""
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            when_true, when_false = self._guard(test.operand, env)
            return when_false, when_true
        if isinstance(test, ast.BoolOp):
            parts = [self._guard(value, env) for value in test.values]
            if isinstance(test.op, ast.And):
                return [item for part in parts for item in part[0]], []
            return [], [item for part in parts for item in part[1]]
        if isinstance(test, ast.Compare) and len(test.ops) == 1:
            operator = test.ops[0]
            left, right = test.left, test.comparators[0]
            if isinstance(operator, (ast.Is, ast.IsNot)) and isinstance(right, ast.Constant) and right.value is None:
                inner_true, inner_false = self._guard(left, env)
                # "x is None" is true exactly when x is falsy for match objects.
                return (inner_false, inner_true) if isinstance(operator, ast.Is) else (inner_true, inner_false)
            if isinstance(operator, (ast.Eq, ast.NotEq)):
                subject = left if isinstance(right, ast.Constant) else right if isinstance(left, ast.Constant) else None
                other = right if subject is left else left
                if subject is not None and isinstance(other, ast.Constant) and isinstance(other.value, str):
                    sanitized = [(name, ALL_SINKS) for name in self._guarded_names(subject, env)]
                    sanitized += self._host_guard(subject, env)
                    return (sanitized, []) if isinstance(operator, ast.Eq) else ([], sanitized)
            if isinstance(operator, (ast.In, ast.NotIn)):
                names = self._guarded_names(left, env)
                if names and self._is_allowlist(right, env):
                    sanitized = [(name, ALL_SINKS) for name in names] + self._host_guard(left, env)
                    return (sanitized, []) if isinstance(operator, ast.In) else ([], sanitized)
                if isinstance(right, ast.Attribute) and right.attr == "parents":
                    names = self._guarded_names(right.value, env)
                    if names and NORMALIZED in self.expression(right.value, env).sanitized:
                        sanitized = [(name, frozenset({FILESYSTEM})) for name in names]
                        return (sanitized, []) if isinstance(operator, ast.In) else ([], sanitized)
            if isinstance(operator, (ast.Eq, ast.NotEq)) and _is_commonpath_check(left, right):
                candidate = _commonpath_candidate(left)
                if candidate is not None and NORMALIZED in self.expression(candidate, env).sanitized:
                    names = self._guarded_names(candidate, env)
                    sanitized = [(name, frozenset({FILESYSTEM})) for name in names]
                    return (sanitized, []) if isinstance(operator, ast.Eq) else ([], sanitized)
        if isinstance(test, ast.Call):
            return self._guard_call(test, env), []
        return [], []

    def _guard_call(self, call: ast.Call, env: dict[str, Value]) -> list[tuple[str, frozenset[str]]]:
        name = self.canonical(call.func)
        short = _short_name(call, name)
        if isinstance(call.func, ast.Attribute) and short in _CHARACTER_PREDICATES and not call.args:
            return [(item, ALL_SINKS) for item in self._guarded_names(call.func.value, env)]
        if isinstance(call.func, ast.Attribute) and short in {"is_relative_to", "startswith"} and call.args:
            receiver = call.func.value
            if NORMALIZED in self.expression(receiver, env).sanitized:
                return [(item, frozenset({FILESYSTEM})) for item in self._guarded_names(receiver, env)]
            return []
        if name in _REDIRECT_GUARDS or short in {"url_has_allowed_host_and_scheme", "is_safe_url"}:
            target = call.args[0] if call.args else next((k.value for k in call.keywords if k.arg == "url"), None)
            if target is not None:
                return [(item, frozenset({REDIRECT})) for item in self._guarded_names(target, env)]
            return []
        pattern, subject, anchored = self._regex_check(call, env)
        if pattern is not None and subject is not None:
            categories = safe_for(pattern, anchored)
            if categories:
                return [(item, categories) for item in self._guarded_names(subject, env)]
        return []

    def _regex_check(self, call: ast.Call, env: dict[str, Value]) -> tuple[str | None, ast.expr | None, bool]:
        name = self.canonical(call.func)
        if name in {"re.fullmatch", "re.match"} and len(call.args) >= 2:
            pattern = self.expression(call.args[0], env)
            if isinstance(pattern.literal, str) and not _has_multiline_flag(call):
                return pattern.literal, call.args[1], name == "re.fullmatch"
        if isinstance(call.func, ast.Attribute) and call.func.attr in {"fullmatch", "match"} and call.args:
            compiled = self.expression(call.func.value, env)
            if isinstance(compiled.literal, tuple) and len(compiled.literal) == 2 and compiled.literal[0] == "re.compile":
                return compiled.literal[1], call.args[0], call.func.attr == "fullmatch"
        return None, None, False

    def _guarded_names(self, node: ast.expr, env: dict[str, Value]) -> list[str]:
        key = _strict_dotted(node)
        if not key:
            return []
        names = [key]
        value = env.get(key)
        if value is not None:
            names.extend(value.derived_from)
        return names

    def _host_guard(self, node: ast.expr, env: dict[str, Value]) -> list[tuple[str, frozenset[str]]]:
        """``parsed.hostname in ALLOWED`` protects the URL that ``parsed`` came from."""
        if not isinstance(node, ast.Attribute) or node.attr not in {"hostname", "netloc", "host"}:
            return []
        root = _strict_dotted(node.value)
        value = env.get(root)
        if not root or value is None:
            return []
        categories = frozenset({HTTP_REQUEST, REDIRECT})
        return [(name, categories) for name in (root, *value.derived_from)]

    def _is_allowlist(self, node: ast.expr, env: dict[str, Value]) -> bool:
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return bool(node.elts) and all(isinstance(item, ast.Constant) for item in node.elts)
        if isinstance(node, ast.Dict):
            return bool(node.keys) and all(isinstance(item, ast.Constant) for item in node.keys)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "keys":
            return self._is_allowlist(node.func.value, env)
        value = self.expression(node, env)
        return isinstance(value.literal, (tuple, frozenset)) and bool(value.literal) and not value.tainted

    def _apply_guard(self, env: dict[str, Value], sanitizations: list[tuple[str, frozenset[str]]]) -> dict[str, Value]:
        for name, categories in sanitizations:
            if name in env:
                env[name] = sanitize(env[name], categories)
        return env

    def _apply_raising_check(self, node: ast.expr, env: dict[str, Value]) -> None:
        """``candidate.relative_to(base)`` raises unless candidate is inside base."""
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "relative_to"
            and node.args
        ):
            receiver = node.func.value
            if NORMALIZED in self.expression(receiver, env).sanitized:
                self._apply_guard(env, [(name, frozenset({FILESYSTEM})) for name in self._guarded_names(receiver, env)])

    # Expressions ----------------------------------------------------------------

    def expression(self, node: ast.AST | None, env: dict[str, Value]) -> Value:
        if node is None:
            return Value()
        source = self._source(node)
        if source is not None:
            return source
        if isinstance(node, ast.Constant):
            return constant(node.value)
        if isinstance(node, ast.Name):
            return env.get(node.id, UNKNOWN)
        if isinstance(node, ast.Attribute):
            key = _strict_dotted(node)
            if key and key in env:
                return env[key]
            base = self.expression(node.value, env)
            if node.attr in {"name", "stem", "suffix"} and base.origin and base.origin.startswith("pathlib."):
                return sanitize(replace(base, origin=None), {FILESYSTEM})
            if base.constant:
                return Value(dynamic=False) if not base.tainted else base
            return replace(base, literal=NOT_CONSTANT, prefix=None, composed=False)
        if isinstance(node, ast.Subscript):
            container = self.expression(node.value, env)
            index = self.expression(node.slice, env)
            return replace(merge(container, index), literal=NOT_CONSTANT, prefix=None, origin=container.origin)
        if isinstance(node, ast.Call):
            return self._call(node, env)
        if isinstance(node, ast.JoinedStr):
            return concatenate([self.expression(value, env) for value in node.values])
        if isinstance(node, ast.FormattedValue):
            return self.expression(node.value, env)
        if isinstance(node, ast.BinOp):
            left = self.expression(node.left, env)
            right = self.expression(node.right, env)
            if isinstance(node.op, ast.Add):
                return concatenate([left, right])
            if isinstance(node.op, ast.Mod) and (isinstance(left.literal, str) or left.prefix is not None):
                return concatenate([left, right])
            if isinstance(node.op, ast.Div) and left.origin and left.origin.startswith("pathlib."):
                joined = merge(left, right)
                return replace(joined, origin=left.origin, literal=NOT_CONSTANT, prefix=None, sanitized=joined.sanitized - {NORMALIZED})
            merged = merge(left, right)
            if left.constant and right.constant:
                return merged
            return replace(merged, literal=NOT_CONSTANT, prefix=None)
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            values = [self.expression(item, env) for item in node.elts]
            merged = merge(*values) if values else Value()
            if values and all(item.constant for item in values):
                literal = tuple(item.literal for item in values)
                return replace(merged, literal=frozenset(literal) if isinstance(node, ast.Set) else literal)
            return replace(merged, literal=NOT_CONSTANT, prefix=None)
        if isinstance(node, ast.Dict):
            values = [self.expression(item, env) for item in [*node.keys, *node.values] if item is not None]
            merged = merge(*values) if values else Value()
            keys = [self.expression(item, env) for item in node.keys if item is not None]
            if keys and all(item.constant for item in keys) and len(keys) == len(node.keys):
                return replace(merged, literal=tuple(item.literal for item in keys), prefix=None)
            return replace(merged, literal=NOT_CONSTANT, prefix=None)
        if isinstance(node, ast.BoolOp):
            return replace(merge(*(self.expression(item, env) for item in node.values)), literal=NOT_CONSTANT)
        if isinstance(node, ast.IfExp):
            self.expression(node.test, env)
            when_true, when_false = self._guard(node.test, env)
            body = self.expression(node.body, self._apply_guard(dict(env), when_true))
            orelse = self.expression(node.orelse, self._apply_guard(dict(env), when_false))
            return merge(body, orelse)
        if isinstance(node, ast.NamedExpr):
            value = self.expression(node.value, env)
            self.bind(node.target, value, env)
            return value
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            return self._comprehension(node, env)
        if isinstance(node, (ast.Compare, ast.UnaryOp)):
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.expr):
                    self.expression(child, env)
            return Value(dynamic=True, sanitized=ALL_SINKS)
        if isinstance(node, ast.Lambda):
            return UNKNOWN
        if isinstance(node, (ast.Await, ast.Starred, ast.Yield, ast.YieldFrom)):
            inner = getattr(node, "value", None)
            return self.expression(inner, env) if inner is not None else UNKNOWN
        values = [self.expression(child, env) for child in ast.iter_child_nodes(node) if isinstance(child, ast.expr)]
        return merge(*values) if values else UNKNOWN

    def _comprehension(self, node: ast.ListComp | ast.SetComp | ast.GeneratorExp | ast.DictComp, env: dict[str, Value]) -> Value:
        inner = dict(env)
        for generator in node.generators:
            iterable = self.expression(generator.iter, inner)
            self.bind(generator.target, iterable, inner)
            for condition in generator.ifs:
                self.expression(condition, inner)
        if isinstance(node, ast.DictComp):
            result = merge(self.expression(node.key, inner), self.expression(node.value, inner))
        else:
            result = self.expression(node.elt, inner)
        return replace(result, literal=NOT_CONSTANT, prefix=None, dynamic=True)

    def _source(self, node: ast.AST) -> Value | None:
        target = node.func if isinstance(node, ast.Call) else node
        if not isinstance(target, (ast.Attribute, ast.Name)):
            return None
        raw = _strict_dotted(target)
        if not raw:
            return None
        name = _canonical_text(self.module, raw)
        parts = name.split(".")
        trust = None
        description = ""
        origin = None
        if isinstance(node, ast.Call):
            if name in _LOCAL_CALLS:
                trust, description = LOCAL, f"Interactive or stdin input from {name}()."
            elif name in _ENV_CALLS:
                trust, description = ENVIRONMENT, f"Environment variable read by {name}()."
            elif parts[-1] in {"parse_args", "parse_known_args"}:
                trust, description = LOCAL, "Command-line arguments parsed by argparse."
            elif parts[-1] in _TORNADO_INPUT and parts[0] == "self":
                trust, description = REMOTE, f"HTTP input from {name}()."
        if trust is None:
            if name == "sys.argv" or name.startswith("sys.argv."):
                trust, description = LOCAL, "Command-line argument from sys.argv."
            elif name == "sys.stdin":
                trust, description = LOCAL, "Standard input."
            elif name == "os.environ" or name == "os.environb":
                trust, description = ENVIRONMENT, "Environment variable from os.environ."
            else:
                for index, part in enumerate(parts[:-1]):
                    attribute = parts[index + 1]
                    if (part == "request" or name.startswith("flask.request")) and attribute in _REQUEST_ATTRIBUTES:
                        trust = REMOTE
                        description = f"HTTP {_REQUEST_ATTRIBUTES[attribute]} from {'.'.join(parts[: index + 2])}."
                        origin = "upload" if attribute in {"files", "FILES"} else None
                        break
        if trust is None:
            return None
        # Only the outermost matching node becomes the SOURCE step; deeper
        # attribute accesses (request.args.get) evaluate through the receiver.
        step = FlowStep("SOURCE", self.location(node), self.code(node), description)
        return replace(source_value(step, trust), origin=origin)

    def _call(self, node: ast.Call, env: dict[str, Value]) -> Value:
        name = self.canonical(node.func)
        short = _short_name(node, name)
        receiver_node = node.func.value if isinstance(node.func, ast.Attribute) else None
        receiver = self.expression(receiver_node, env) if receiver_node is not None else Value()
        if receiver_node is not None and _is_module_reference(receiver_node, self.module, env):
            receiver = Value()
        arguments = [self.expression(item, env) for item in node.args]
        keywords = {item.arg: self.expression(item.value, env) for item in node.keywords if item.arg}
        for item in node.keywords:
            if item.arg is None:
                self.expression(item.value, env)

        resolved = self.project.resolve(self.module, self.function, node.func)
        actuals = self._actuals(resolved, receiver, arguments, keywords) if resolved else None
        if resolved is not None:
            self._call_summary_sinks(node, resolved, actuals)
        self._check_sinks(node, name, receiver, arguments, keywords, env)

        if name in _SANITIZERS:
            return sanitize(replace(merge(*arguments, *keywords.values()), origin=None, composed=False), _SANITIZERS[name])
        if name in _NORMALIZERS:
            return sanitize(merge(*arguments), {NORMALIZED})
        if short in _PATH_RETURNING_METHODS and receiver.origin and receiver.origin.startswith("pathlib."):
            value = replace(merge(receiver, *arguments), origin=receiver.origin, literal=NOT_CONSTANT)
            if short == "resolve" or short == "absolute":
                value = sanitize(value, {NORMALIZED})
            else:
                value = replace(value, sanitized=value.sanitized - {NORMALIZED})
            return value
        if name in {"re.compile", "regex.compile"} and arguments and isinstance(arguments[0].literal, str):
            return Value(literal=("re.compile", arguments[0].literal))
        if name in {"urllib.parse.urlparse", "urllib.parse.urlsplit"} and node.args:
            parsed = merge(*arguments)
            return replace(parsed, derived_from=(*parsed.derived_from, *([_dotted(node.args[0])] if _dotted(node.args[0]) else [])), literal=NOT_CONSTANT, prefix=None)
        if resolved is not None:
            return self._summary_return(resolved, actuals or {})
        if short == "format" and receiver.constant and isinstance(receiver.literal, str):
            return concatenate([receiver, *arguments, *keywords.values()])
        if short == "join" and receiver.constant and isinstance(receiver.literal, str):
            return concatenate([*arguments])
        combined = merge(receiver, *arguments, *keywords.values())
        pure = name in _PURE_FUNCTIONS or (short in _STRING_METHODS and receiver_node is not None and not receiver.dynamic)
        if pure and not combined.dynamic and not combined.tainted:
            return replace(combined, origin=_origin(name), literal=NOT_CONSTANT, prefix=None)
        return replace(
            combined,
            dynamic=True,
            origin=_origin(name),
            literal=NOT_CONSTANT,
            prefix=None,
            composed=False,
            sanitized=combined.sanitized - {NORMALIZED},
        )

    def _actuals(
        self,
        resolved: tuple[Module, FunctionInfo, bool],
        receiver: Value,
        arguments: list[Value],
        keywords: dict[str, Value],
    ) -> dict[int, Value]:
        _, info, bound = resolved
        positional = [receiver, *arguments] if bound else arguments
        names = (*info.params, *info.kwonly)
        actuals = {index: value for index, value in enumerate(positional) if index < len(info.params)}
        for keyword, value in keywords.items():
            if keyword in names:
                actuals[names.index(keyword)] = value
        return actuals

    def _summary_return(self, resolved: tuple[Module, FunctionInfo, bool], actuals: dict[int, Value]) -> Value:
        module, info, _ = resolved
        summary = self.project.summaries.get((module.relative, info.qualname))
        if summary is None or summary.returned is None:
            return UNKNOWN
        returned = summary.returned
        from_params = [actuals[index] for index in sorted(returned.params) if index in actuals]
        own = replace(returned, params=frozenset())
        parts = [own] if own.tainted or own.dynamic or own.constant else []
        value = merge(*from_params, *parts) if (from_params or parts) else Value(dynamic=True)
        sanitized = value.sanitized | (returned.sanitized if returned.params else frozenset())
        return replace(
            value,
            sanitized=sanitized,
            dynamic=value.dynamic or returned.dynamic,
            origin=returned.origin,
            composed=value.composed or returned.composed,
        )

    def _call_summary_sinks(self, node: ast.Call, resolved: tuple[Module, FunctionInfo, bool], actuals: dict[int, Value] | None) -> None:
        module, info, _ = resolved
        summary = self.project.summaries.get((module.relative, info.qualname))
        if summary is None or not actuals:
            return
        call_step = FlowStep(
            "PROPAGATION",
            self.location(node),
            self.code(node),
            f"Value is passed to {info.qualname}().",
        )
        for template in summary.sinks:
            relevant = [actuals[index] for index in sorted(template.value.params) if index in actuals]
            if not relevant:
                continue
            actual = merge(*relevant)
            category = rule(template.rule_id).category
            if category in template.value.sanitized:
                continue
            propagated = replace(
                actual,
                flow=unique_steps((*actual.flow, call_step, *template.value.flow)),
                sanitized=actual.sanitized | template.value.sanitized,
            )
            if self.summary is not None:
                if propagated.params:
                    self._add_template(template.rule_id, template.node, template.sink, propagated, template.certainty, template.module, template.function, template.sql_evidence)
                continue
            if self.findings is None:
                continue
            confidence = judge(
                category,
                propagated,
                certainty=template.certainty,
                unknown_origin=True,
                sql_evidence=template.sql_evidence or bool(SQL_KEYWORDS.search(actual.text)),
            )
            if confidence is None or not (propagated.sources or propagated.composed):
                continue
            self._report(
                template.rule_id,
                template.node,
                template.sink,
                propagated,
                confidence,
                module=template.module,
                function=template.function,
                related=[self.location(node)],
            )

    # Sinks ------------------------------------------------------------------------

    def _check_sinks(
        self,
        node: ast.Call,
        name: str,
        receiver: Value,
        arguments: list[Value],
        keywords: dict[str, Value],
        env: dict[str, Value],
    ) -> None:
        for rule_id, sink, value, certainty, options in self._sinks(node, name, receiver, arguments, keywords, env):
            self._sink_reached(node, rule_id, sink, value, certainty, **options)

    def _sinks(self, node: ast.Call, name: str, receiver: Value, arguments: list[Value], keywords: dict[str, Value], env: dict[str, Value]):
        short = _short_name(node, name)

        def argument(index: int, keyword: str | None = None) -> Value | None:
            if keyword and keyword in keywords:
                return keywords[keyword]
            return arguments[index] if index < len(arguments) else None

        # Command execution.
        if name in _SHELL_STRING_CALLS:
            command = argument(0, "cmd")
            if command is not None:
                yield "PY-CMD-001", name, command, Confidence.HIGH, {"unknown_origin": True}
            return
        if name in _SUBPROCESS_CALLS:
            command = argument(0, "args")
            if command is None:
                return
            shell = keywords.get("shell")
            if shell is not None and shell.constant and shell.literal is True:
                yield "PY-CMD-001", f"{name}(shell=True)", command, Confidence.HIGH, {"unknown_origin": True}
            elif shell is not None and not shell.constant:
                yield "PY-CMD-001", f"{name}(shell=<dynamic>)", command, Confidence.MEDIUM, {"unknown_origin": False}
            else:
                program = self._program_value(node.args[0] if node.args else None, command, env)
                if program is not None:
                    yield "PY-CMD-001", f"{name} program path", program, Confidence.HIGH, {"unknown_origin": False}
            return
        if name in _PROGRAM_CALLS:
            program = argument(0)
            if program is not None:
                yield "PY-CMD-001", f"{name} program path", program, Confidence.HIGH, {"unknown_origin": False}
            return
        # Code execution.
        if name in _CODE_CALLS:
            code = argument(0)
            if code is not None:
                yield "PY-CODE-001", name, code, Confidence.HIGH, {"unknown_origin": True}
            return
        if name in {"compile", "builtins.compile"} and len(arguments) >= 3:
            mode = argument(2, "mode")
            if mode is not None and mode.literal in {"exec", "eval", "single"}:
                yield "PY-CODE-001", name, arguments[0], Confidence.HIGH, {"unknown_origin": True}
            return
        # SQL.
        if short in {"execute", "executemany", "executescript", "query", "raw", "read_sql", "read_sql_query"} and isinstance(node.func, ast.Attribute):
            statement = argument(0, "sql")
            if statement is None:
                statement = keywords.get("statement") or keywords.get("query")
            if statement is None:
                return
            receiver_name = self.canonical(node.func.value)
            evidence = bool(SQL_KEYWORDS.search(statement.text)) or (isinstance(statement.literal, str) and bool(SQL_KEYWORDS.search(statement.literal)))
            database_receiver = bool(_DB_RECEIVER.search(receiver_name)) or receiver_name.startswith(("pandas", "sqlite3", "psycopg"))
            if short in {"query"} and not evidence:
                return
            if short == "raw" and "objects" not in receiver_name:
                return
            certainty = Confidence.HIGH if evidence or database_receiver else Confidence.MEDIUM
            yield "PY-SQL-001", name, statement, certainty, {"unknown_origin": True, "sql_evidence": evidence}
            return
        # Deserialization.
        if name in _DESERIALIZERS:
            data = argument(0)
            if data is not None:
                yield "PY-DESER-001", name, data, Confidence.HIGH, {}
            return
        if name in {"yaml.load", "yaml.load_all"} and arguments:
            loader = next((item.value for item in node.keywords if item.arg in {"Loader", "loader"}), None)
            if loader is None and len(node.args) >= 2:
                loader = node.args[1]
            loader_name = self.canonical(loader) if loader is not None else ""
            if loader_name.endswith(_SAFE_YAML_LOADERS):
                return
            yield "PY-DESER-001", name, arguments[0], Confidence.HIGH, {}
            return
        if name == "numpy.load" and arguments:
            allow = keywords.get("allow_pickle")
            if allow is not None and allow.literal is True:
                yield "PY-DESER-001", "numpy.load(allow_pickle=True)", arguments[0], Confidence.HIGH, {}
            return
        # Template injection.
        if name in _TEMPLATE_CALLS or (short == "from_string" and isinstance(node.func, ast.Attribute)):
            template = argument(0, "source") or keywords.get("text")
            if template is not None:
                yield "PY-SSTI-001", name, template, Confidence.HIGH, {}
            return
        # Redirects.
        if name in _REDIRECT_CALLS:
            target = argument(0, "location") or keywords.get("url") or keywords.get("redirect_to") or keywords.get("to")
            if target is not None and not is_local_path(target.prefix):
                yield "OPEN-REDIRECT-001", name, target, Confidence.HIGH, {}
            return
        # Outbound requests.
        url_index = _HTTP_FUNCTIONS.get(name)
        if url_index is None and short in _HTTP_CLIENT_METHODS and receiver.origin in _HTTP_CLIENT_ORIGINS:
            url_index = _HTTP_CLIENT_METHODS[short]
        if url_index is not None:
            target = argument(url_index, "url")
            if target is not None and not has_fixed_host(target.prefix):
                yield "PY-SSRF-001", name, target, Confidence.HIGH, {}
            return
        # XML.
        if name in _LXML_PARSE and arguments:
            if not any(item.arg == "parser" for item in node.keywords) and len(node.args) < 2:
                yield "PY-XXE-001", name, arguments[0], Confidence.MEDIUM, {}
            return
        # Filesystem.
        if name in _PATH_CALLS:
            paths = [value for value in (argument(0, "file"), argument(1, "dst") if name in _TWO_PATH_CALLS else None) if value is not None]
            for path in paths:
                yield "PY-PATH-001", name, path, Confidence.HIGH, {}
            return
        if isinstance(node.func, ast.Attribute):
            if short in _PATH_METHODS_ANY_RECEIVER or (
                short in _PATH_METHODS_PATHLIB and receiver.origin and receiver.origin.startswith("pathlib.")
            ):
                yield "PY-PATH-001", f"Path.{short}", receiver, Confidence.HIGH, {}
                return
            if short == "save" and receiver.origin == "upload" and arguments:
                yield "PY-PATH-001", "uploaded file save()", arguments[0], Confidence.HIGH, {}

    def _program_value(self, node: ast.expr | None, value: Value, env: dict[str, Value]) -> Value | None:
        """Value that selects the executed program when no shell is used."""
        if isinstance(node, (ast.List, ast.Tuple)):
            if not node.elts or isinstance(node.elts[0], ast.Starred):
                return None
            return self.expression(node.elts[0], env)
        if value.composed or isinstance(node, (ast.JoinedStr, ast.BinOp)):
            return value
        if value.sources and isinstance(node, (ast.Name, ast.Subscript, ast.Call, ast.Attribute)):
            # A request parameter is a string: without a shell it names the program.
            return value
        return None

    def _sink_reached(
        self,
        node: ast.Call,
        rule_id: str,
        sink: str,
        value: Value,
        certainty: Confidence,
        *,
        unknown_origin: bool = False,
        sql_evidence: bool = True,
    ) -> None:
        category = rule(rule_id).category
        if self.summary is not None:
            if value.params and category not in value.sanitized:
                self._add_template(rule_id, node, sink, value, certainty, self.module, self.function_name, sql_evidence)
            return
        if self.findings is None:
            return
        confidence = judge(category, value, certainty=certainty, unknown_origin=unknown_origin, sql_evidence=sql_evidence)
        if confidence is not None:
            self._report(rule_id, node, sink, value, confidence)

    def _add_template(self, rule_id: str, node: ast.Call, sink: str, value: Value, certainty: Confidence, module: Module, function: str | None, sql_evidence: bool) -> None:
        assert self.summary is not None
        key = (rule_id, module.relative, node.lineno, node.col_offset, tuple(sorted(value.params)))
        for existing in self.summary.sinks:
            if (existing.rule_id, existing.module.relative, existing.node.lineno, existing.node.col_offset, tuple(sorted(existing.value.params))) == key:
                return
        self.summary.sinks.append(SinkTemplate(rule_id, module, node, sink, value, certainty, function, sql_evidence))

    def _report(
        self,
        rule_id: str,
        node: ast.Call,
        sink: str,
        value: Value,
        confidence: Confidence,
        *,
        module: Module | None = None,
        function: str | None = None,
        related: list[Location] | None = None,
    ) -> None:
        assert self.findings is not None
        if module is None:
            module, function = self.module, self.function_name
        definition = rule(rule_id)
        location = _location(module, node, function)
        code = _code(module, node)
        sink_step = FlowStep("SINK", location, code, f"Value reaches {sink}.")
        flow = list(unique_steps((*value.flow, sink_step)))
        source = next((step.location for step in flow if step.kind == "SOURCE"), None)
        reason = definition.explanation
        if source is None:
            reason += " The value is built at runtime from data whose origin the analyzer could not determine."
        elif value.trust == LOCAL:
            reason += " The source is local input (command line or stdin), so exploitation needs a caller that passes untrusted data."
        elif value.trust == ENVIRONMENT:
            reason += " The source is an environment variable, which an attacker rarely controls."
        related_locations = list(related or [])
        if source is not None and source.file != location.file:
            related_locations.insert(0, source)
        suggestion = patches.python_suggestion(rule_id, node, module.text, module.imports)
        self.findings.append(
            Finding(
                rule_id=rule_id,
                name=definition.name,
                cwe=definition.cwe,
                severity=definition.severity,
                confidence=confidence,
                category=definition.category,
                language="Python",
                location=location,
                sink=sink,
                evidence=code,
                reason=reason,
                source=source,
                flow=flow,
                related_locations=_unique_locations(related_locations),
                remediations=remediations_for(rule_id, code, suggestion),
            )
        )

    # Helpers ----------------------------------------------------------------------

    def canonical(self, node: ast.AST | None) -> str:
        return _canonical(self.module, node)

    def location(self, node: ast.AST) -> Location:
        return _location(self.module, node, self.function_name)

    def code(self, node: ast.AST) -> str:
        return _code(self.module, node)



def _origin(name: str) -> str | None:
    return name or None


def _short_name(call: ast.Call, name: str) -> str:
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    return name.rsplit(".", 1)[-1] if name else ""


def _canonical(module: Module, node: ast.AST | None) -> str:
    return _canonical_text(module, _dotted(node))


def _canonical_text(module: Module, raw: str) -> str:
    if not raw:
        return ""
    first, dot, rest = raw.partition(".")
    replacement = module.imports.get(first)
    return f"{replacement}{dot}{rest}" if replacement else raw


def _strict_dotted(node: ast.AST | None) -> str:
    """Dotted name made only of names and attributes (no calls or subscripts)."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _strict_dotted(node.value)
        return f"{parent}.{node.attr}" if parent else ""
    return ""


def _dotted(node: ast.AST | None) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted(node.value)
        return f"{parent}.{node.attr}" if parent else ""
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    if isinstance(node, ast.Subscript):
        return _dotted(node.value)
    return ""


def _is_module_reference(node: ast.expr, module: Module, env: dict[str, Value]) -> bool:
    root = node
    while isinstance(root, ast.Attribute):
        root = root.value
    return isinstance(root, ast.Name) and root.id in module.imports and root.id not in env


def _location(module: Module, node: ast.AST, function: str | None) -> Location:
    line = max(getattr(node, "lineno", 1), 1)
    end_line = getattr(node, "end_lineno", None) or line
    text_line = module.lines[line - 1] if line - 1 < len(module.lines) else ""
    column = utf8_column_to_char(text_line, getattr(node, "col_offset", 0)) + 1
    end_column = None
    if getattr(node, "end_col_offset", None) is not None:
        end_text = module.lines[end_line - 1] if end_line - 1 < len(module.lines) else ""
        end_column = utf8_column_to_char(end_text, node.end_col_offset) + 1
    return Location(module.relative, line, column, end_line, end_column, function)


def _code(module: Module, node: ast.AST) -> str:
    segment = ast.get_source_segment(module.text, node)
    if not segment:
        try:
            segment = ast.unparse(node)
        except (AttributeError, ValueError):
            segment = node.__class__.__name__
    return " ".join(segment.split())[:500]


def _unique_locations(items: list[Location]) -> list[Location]:
    seen: set[tuple[str, int, int | None]] = set()
    result: list[Location] = []
    for item in items:
        key = (item.file, item.line, item.column)
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


def _merge_environments(left: dict[str, Value], right: dict[str, Value]) -> dict[str, Value]:
    result: dict[str, Value] = {}
    for key in left.keys() | right.keys():
        if key in left and key in right:
            result[key] = left[key] if left[key] is right[key] else merge(left[key], right[key])
        else:
            result[key] = merge(left.get(key, UNKNOWN), right.get(key, UNKNOWN))
    return result


def _merge_all(environments: list[dict[str, Value]]) -> dict[str, Value]:
    result = environments[0]
    for environment in environments[1:]:
        result = _merge_environments(result, environment)
    return result


def _terminates(statements: Sequence[ast.stmt]) -> bool:
    if not statements:
        return False
    last = statements[-1]
    if isinstance(last, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
        return True
    if isinstance(last, ast.Expr) and isinstance(last.value, ast.Call):
        name = _dotted(last.value.func)
        return name in _ABORT_CALLS or name.rsplit(".", 1)[-1] == "abort"
    if isinstance(last, ast.If):
        return _terminates(last.body) and _terminates(last.orelse)
    return False


def _has_multiline_flag(call: ast.Call) -> bool:
    for node in [*call.args[2:], *(item.value for item in call.keywords if item.arg == "flags")]:
        if "MULTILINE" in ast.dump(node) or re.search(r"\bM\b", ast.dump(node)):
            return True
    return False


def _is_commonpath_check(left: ast.expr, right: ast.expr) -> bool:
    return isinstance(left, ast.Call) and _dotted(left.func) in {"os.path.commonpath", "commonpath"}


def _commonpath_candidate(call: ast.expr) -> ast.expr | None:
    if isinstance(call, ast.Call) and call.args and isinstance(call.args[0], (ast.List, ast.Tuple)) and len(call.args[0].elts) == 2:
        return call.args[0].elts[1]
    return None


def _pattern_names(pattern: ast.AST) -> list[str]:
    names: list[str] = []
    for node in ast.walk(pattern):
        if isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            names.append(node.name)
    return names


def _module_statements(tree: ast.Module) -> list[ast.stmt]:
    return [node for node in tree.body if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]


def _assigned_names(statement: ast.stmt) -> list[str]:
    names: list[str] = []
    targets: list[ast.AST] = []
    if isinstance(statement, ast.Assign):
        targets = list(statement.targets)
    elif isinstance(statement, (ast.AnnAssign, ast.AugAssign)):
        targets = [statement.target]
    elif isinstance(statement, (ast.For, ast.AsyncFor)):
        targets = [statement.target]
    elif isinstance(statement, (ast.With, ast.AsyncWith)):
        targets = [item.optional_vars for item in statement.items if item.optional_vars is not None]
    elif isinstance(statement, (ast.Import, ast.ImportFrom)):
        return [(alias.asname or alias.name).split(".")[0] for alias in statement.names]
    for target in targets:
        for node in ast.walk(target):
            if isinstance(node, ast.Name):
                names.append(node.id)
    for child in ast.iter_child_nodes(statement):
        if isinstance(child, ast.stmt):
            names.extend(_assigned_names(child))
    return names


def _module_name(relative: str) -> tuple[str, str]:
    parts = relative.replace("\\", "/").split("/")
    stem = parts[-1].rsplit(".", 1)[0]
    if stem == "__init__":
        package_parts = parts[:-1]
        return ".".join(package_parts), ".".join(package_parts)
    package_parts = parts[:-1]
    return ".".join([*package_parts, stem]), ".".join(package_parts)


def _collect_symbols(module: Module) -> None:
    for node in ast.walk(module.tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    module.imports[alias.asname] = alias.name
                else:
                    first = alias.name.split(".")[0]
                    module.imports.setdefault(first, first)
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                package = module.package.split(".") if module.package else []
                keep = len(package) - (node.level - 1)
                if keep < 0:
                    continue
                base = ".".join([*package[:keep], *([base] if base else [])])
            for alias in node.names:
                if alias.name == "*":
                    continue
                module.imports[alias.asname or alias.name] = f"{base}.{alias.name}".strip(".")

    def add_function(node: ast.FunctionDef | ast.AsyncFunctionDef, qualname: str, class_name: str | None) -> None:
        decorators = {_dotted(item.func if isinstance(item, ast.Call) else item) for item in node.decorator_list}
        static = "staticmethod" in decorators
        positional = [*node.args.posonlyargs, *node.args.args]
        module.functions[qualname] = FunctionInfo(
            qualname,
            node,
            class_name,
            receives_instance=class_name is not None and not static,
            params=tuple(item.arg for item in positional),
            kwonly=tuple(item.arg for item in node.args.kwonlyargs),
        )
        for child in node.body:
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                add_function(child, f"{qualname}.{child.name}", None)

    for node in module.tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            add_function(node, node.name, None)
        elif isinstance(node, ast.ClassDef):
            module.classes.add(node.name)
            for child in node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    add_function(child, f"{node.name}.{child.name}", node.name)


def _route_inputs(node: ast.FunctionDef | ast.AsyncFunctionDef, module: Module) -> list[tuple[ast.arg, bool]]:
    """Return (parameter, sanitized) pairs for HTTP handler inputs."""
    route = False
    path_names: dict[str, bool] = {}
    flask_style = False
    for decorator in node.decorator_list:
        call = decorator if isinstance(decorator, ast.Call) else None
        name = _canonical(module, call.func if call else decorator)
        if name.rsplit(".", 1)[-1] not in _ROUTE_DECORATORS:
            continue
        route = True
        if call and call.args and isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str):
            path = call.args[0].value
            for converter, variable in re.findall(r"<(?:(\w+)(?:\([^)]*\))?:)?([A-Za-z_]\w*)>", path):
                flask_style = True
                path_names[variable] = converter in {"int", "float", "uuid"}
            for variable, converter in re.findall(r"\{([A-Za-z_]\w*)(?::(\w+))?\}", path):
                path_names.setdefault(variable, converter in {"int", "float", "uuid"})
    if not route:
        return []
    arguments = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
    defaults: dict[str, ast.expr] = {}
    positional = [*node.args.posonlyargs, *node.args.args]
    for argument, default in zip(positional[len(positional) - len(node.args.defaults):], node.args.defaults):
        defaults[argument.arg] = default
    for argument, default in zip(node.args.kwonlyargs, node.args.kw_defaults):
        if default is not None:
            defaults[argument.arg] = default
    result: list[tuple[ast.arg, bool]] = []
    for argument in arguments:
        if argument.arg in _NON_INPUT_PARAMETERS:
            continue
        default = defaults.get(argument.arg)
        default_name = _canonical(module, default.func).rsplit(".", 1)[-1] if isinstance(default, ast.Call) else ""
        if default_name in _INJECTED:
            continue
        annotation = _annotation_name(argument.annotation, module)
        if annotation.rsplit(".", 1)[-1] in _NON_INPUT_ANNOTATIONS:
            continue
        if flask_style and argument.arg not in path_names:
            continue
        sanitized = path_names.get(argument.arg, False) or annotation in _SAFE_ANNOTATIONS or annotation.rsplit(".", 1)[-1] in _SAFE_ANNOTATIONS
        if isinstance(argument.annotation, ast.Subscript) and _dotted(argument.annotation.value).endswith("Literal"):
            sanitized = True
        if default_name in _FASTAPI_INPUTS or not flask_style or argument.arg in path_names:
            result.append((argument, sanitized))
    return result


def _annotation_name(annotation: ast.expr | None, module: Module) -> str:
    if annotation is None:
        return ""
    if isinstance(annotation, ast.Subscript) and _dotted(annotation.value).endswith("Annotated"):
        inner = annotation.slice
        if isinstance(inner, ast.Tuple) and inner.elts:
            return _annotation_name(inner.elts[0], module)
    if isinstance(annotation, ast.BinOp):  # int | None
        left = _annotation_name(annotation.left, module)
        return left if left else _annotation_name(annotation.right, module)
    if isinstance(annotation, ast.Subscript) and _dotted(annotation.value).endswith("Optional"):
        return _annotation_name(annotation.slice, module)
    if isinstance(annotation, ast.Constant) and annotation.value is None:
        return ""
    return _canonical(module, annotation)


# Pattern rules ------------------------------------------------------------------

_HASH_FUNCTIONS = {
    "hashlib.md5",
    "hashlib.sha1",
    "hashlib.sha224",
    "hashlib.sha256",
    "hashlib.sha384",
    "hashlib.sha512",
    "hashlib.sha3_256",
    "hashlib.sha3_512",
    "hashlib.blake2b",
    "hashlib.blake2s",
    "hashlib.new",
}
_WEAK_CIPHER_CALLS = (
    "Cipher.DES.new",
    "Cipher.DES3.new",
    "Cipher.ARC2.new",
    "Cipher.ARC4.new",
    "Cipher.Blowfish.new",
    "algorithms.TripleDES",
    "algorithms.ARC4",
    "algorithms.Blowfish",
    "algorithms.IDEA",
    "algorithms.CAST5",
    "modes.ECB",
)
_RANDOM_CALLS = {
    "random.random",
    "random.randint",
    "random.randrange",
    "random.choice",
    "random.choices",
    "random.sample",
    "random.getrandbits",
    "random.shuffle",
    "random.uniform",
}


def _pattern_findings(module: Module) -> list[Finding]:
    """AST pattern rules that need no data flow."""
    findings: list[Finding] = []
    imports_flask = any(target.split(".")[0] == "flask" for target in module.imports.values())
    module_assignments = {
        target.id: statement
        for statement in module.tree.body
        if isinstance(statement, ast.Assign)
        for target in statement.targets
        if isinstance(target, ast.Name)
    }
    settings_module = bool({"INSTALLED_APPS", "ROOT_URLCONF", "MIDDLEWARE"} & module_assignments.keys())

    def add(rule_id: str, node: ast.AST, function: str | None, sink: str, evidence: str | None = None, suggestion=None) -> None:
        definition = rule(rule_id)
        location = _location(module, node, function)
        code = evidence or _code(module, node)
        findings.append(
            Finding(
                rule_id=rule_id,
                name=definition.name,
                cwe=definition.cwe,
                severity=definition.severity,
                confidence=definition.default_confidence,
                category=definition.category,
                language="Python",
                location=location,
                sink=sink,
                evidence=code,
                reason=definition.explanation,
                remediations=remediations_for(rule_id, code, suggestion),
            )
        )

    def visit(node: ast.AST, function: str | None, hash_objects: dict[str, str]) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            qualname = node.name if function is None else f"{function}.{node.name}"
            if is_random_sensitive_name(node.name):
                for child in ast.walk(node):
                    if isinstance(child, ast.Return) and child.value is not None:
                        call = _random_call(module, child.value)
                        if call is not None:
                            add("WEAK-RANDOM-001", call, qualname, _canonical(module, call.func), suggestion=patches.random_suggestion(module.text, call, _canonical(module, call.func)))
            function_hashes: dict[str, str] = {}
            for child in node.body:
                visit(child, qualname, function_hashes)
            return
        if isinstance(node, ast.ClassDef):
            for child in node.body:
                visit(child, node.name if function is None else f"{function}.{node.name}", {})
            return
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            _assignment_patterns(module, node, function, add, hash_objects, settings_module)
        if isinstance(node, ast.Call):
            _call_patterns(module, node, function, add, hash_objects, imports_flask)
        if isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if (
                    isinstance(key, ast.Constant)
                    and isinstance(key.value, str)
                    and is_credential_name(key.value)
                    and isinstance(value, ast.Constant)
                    and isinstance(value.value, str)
                    and looks_like_secret(value.value, key.value)
                ):
                    add("SECRET-001", value, function, key.value, _redacted(module, value))
        for child in ast.iter_child_nodes(node):
            visit(child, function, hash_objects)

    module_hashes: dict[str, str] = {}
    for statement in module.tree.body:
        visit(statement, None, module_hashes)
    _settings_patterns(module_assignments, add)
    return findings


def _assignment_patterns(module: Module, node: ast.Assign | ast.AnnAssign, function: str | None, add, hash_objects: dict[str, str], settings_module: bool) -> None:
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    value = node.value
    if value is None:
        return
    for target in targets:
        target_name = _target_name(target)
        if not target_name:
            continue
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            if is_credential_name(target_name) and looks_like_secret(value.value, target_name):
                add("SECRET-001", value, function, target_name, _redacted(module, node))
        call = _random_call(module, value)
        if call is not None and is_random_sensitive_name(target_name):
            add("WEAK-RANDOM-001", call, function, _canonical(module, call.func), suggestion=patches.random_suggestion(module.text, call, _canonical(module, call.func)))
        if isinstance(value, ast.Call) and _canonical(module, value.func) in _HASH_FUNCTIONS and isinstance(target, ast.Name):
            hash_objects[target.id] = _canonical(module, value.func)
        if isinstance(value, ast.Constant) and value.value is True:
            if target_name in {"DEBUG"} and function is None and settings_module and isinstance(target, ast.Name):
                add("DEBUG-001", node, function, "Django DEBUG setting", suggestion=patches.line_suggestion(module.text, node, "True", "False"))
            elif isinstance(target, ast.Attribute) and target.attr == "debug" and _dotted(target.value) in {"app", "application"}:
                add("DEBUG-001", node, function, "Flask debug attribute", suggestion=patches.line_suggestion(module.text, node, "True", "False"))
            elif isinstance(target, ast.Subscript) and isinstance(target.slice, ast.Constant) and target.slice.value == "DEBUG" and _dotted(target.value).endswith("config"):
                add("DEBUG-001", node, function, "Flask DEBUG config", suggestion=patches.line_suggestion(module.text, node, "True", "False"))
        if isinstance(value, ast.Constant) and value.value is False and isinstance(target, ast.Attribute) and target.attr == "check_hostname":
            add("TLS-VERIFY-001", node, function, "ssl check_hostname=False")
        if isinstance(target, ast.Attribute) and target.attr == "verify_mode" and _canonical(module, value).endswith("CERT_NONE"):
            add("TLS-VERIFY-001", node, function, "ssl.CERT_NONE")


def _call_patterns(module: Module, node: ast.Call, function: str | None, add, hash_objects: dict[str, str], imports_flask: bool) -> None:
    name = _canonical(module, node.func)
    keywords = {item.arg: item.value for item in node.keywords if item.arg}
    if name.startswith("jwt.") or ".jwt." in name:
        if name.endswith(".decode"):
            if _is_false(keywords.get("verify")):
                add("JWT-VERIFY-001", node, function, name)
            options = keywords.get("options")
            if isinstance(options, ast.Dict) and any(
                isinstance(key, ast.Constant) and key.value == "verify_signature" and _is_false(value)
                for key, value in zip(options.keys, options.values)
            ):
                add("JWT-VERIFY-001", node, function, name)
            algorithms = keywords.get("algorithms")
            if algorithms is not None and any(
                isinstance(item, ast.Constant) and isinstance(item.value, str) and item.value.casefold() == "none"
                for item in ast.walk(algorithms)
            ):
                add("JWT-VERIFY-001", node, function, name)
    else:
        verify = keywords.get("verify")
        if _is_false(verify):
            add("TLS-VERIFY-001", node, function, f"{name or 'call'}(verify=False)", suggestion=patches.keyword_suggestion(module.text, node, "verify", "False", "True"))
        cert_reqs = keywords.get("cert_reqs")
        if cert_reqs is not None and (_canonical(module, cert_reqs).endswith("CERT_NONE") or (isinstance(cert_reqs, ast.Constant) and cert_reqs.value == "CERT_NONE")):
            add("TLS-VERIFY-001", node, function, f"{name}(cert_reqs=CERT_NONE)")
    if name in {"ssl._create_unverified_context", "ssl._create_stdlib_context"}:
        add("TLS-VERIFY-001", node, function, name)
    if name == "tempfile.mktemp":
        add("TEMPFILE-001", node, function, name)
    if name in {"os.chmod", "os.fchmod", "os.lchmod"} or (isinstance(node.func, ast.Attribute) and node.func.attr == "chmod" and not name.startswith("os.")):
        mode = keywords.get("mode") or (node.args[1] if name.startswith("os.") and len(node.args) >= 2 else node.args[0] if not name.startswith("os.") and node.args else None)
        if isinstance(mode, ast.Constant) and isinstance(mode.value, int) and not isinstance(mode.value, bool) and mode.value & 0o002:
            add("FILE-PERM-001", node, function, f"{name or 'chmod'}({oct(mode.value)})")
    if name.endswith(_WEAK_CIPHER_CALLS):
        add("WEAK-CIPHER-001", node, function, name)
    elif name.endswith("AES.new") and any(_canonical(module, item).endswith("MODE_ECB") for item in [*node.args, *keywords.values()]):
        add("WEAK-CIPHER-001", node, function, "AES in ECB mode")
    if name in _HASH_FUNCTIONS and any(mentions_password(_dotted(item) or _constant_text(item)) for argument in node.args for item in ast.walk(argument)):
        add("WEAK-HASH-001", node, function, name)
    elif isinstance(node.func, ast.Attribute) and node.func.attr == "update" and _dotted(node.func.value) in hash_objects:
        if any(mentions_password(_dotted(item)) for argument in node.args for item in ast.walk(argument)):
            add("WEAK-HASH-001", node, function, hash_objects[_dotted(node.func.value)])
    if imports_flask and isinstance(node.func, ast.Attribute) and node.func.attr == "run" and name != "asyncio.run":
        if _is_true(keywords.get("debug")):
            add("DEBUG-001", node, function, "Flask app.run(debug=True)", suggestion=patches.keyword_suggestion(module.text, node, "debug", "True", "False"))
    if name.endswith("lxml.etree.XMLParser") or name == "lxml.etree.XMLParser":
        if _is_true(keywords.get("resolve_entities")) or (_is_true(keywords.get("load_dtd")) and not _is_false(keywords.get("resolve_entities"))):
            add("XXE-001", node, function, name)
    if isinstance(node.func, ast.Attribute) and node.func.attr == "setFeature" and len(node.args) == 2:
        feature = _canonical(module, node.args[0])
        if feature.endswith(("feature_external_ges", "feature_external_pes")) and _is_true(node.args[1]):
            add("XXE-001", node, function, feature)
    for keyword in node.keywords:
        if (
            keyword.arg
            and is_credential_name(keyword.arg)
            and isinstance(keyword.value, ast.Constant)
            and isinstance(keyword.value.value, str)
            and looks_like_secret(keyword.value.value, keyword.arg)
        ):
            add("SECRET-001", keyword.value, function, keyword.arg, _redacted(module, keyword))
    _cors_patterns(module, node, name, keywords, function, add)


def _cors_patterns(module: Module, node: ast.Call, name: str, keywords: dict[str, ast.expr], function: str | None, add) -> None:
    short = name.rsplit(".", 1)[-1]
    if short in {"CORS", "cross_origin"} and (name.startswith("flask_cors") or short == "CORS"):
        if not _is_true(keywords.get("supports_credentials")):
            return
        origins = keywords.get("origins")
        resources = keywords.get("resources")
        resource_origins: list[ast.expr] = []
        if isinstance(resources, ast.Dict):
            for value in resources.values:
                if isinstance(value, ast.Dict):
                    resource_origins.extend(v for k, v in zip(value.keys, value.values) if isinstance(k, ast.Constant) and k.value == "origins")
        candidates = [item for item in (origins, *resource_origins) if item is not None]
        if not candidates or any(_is_wildcard(item) for item in candidates):
            add("CORS-001", node, function, f"{short}(supports_credentials=True) with any origin")
        return
    middleware = node.args[0] if node.args and short == "add_middleware" else None
    if (middleware is not None and _dotted(middleware).endswith("CORSMiddleware")) or short == "CORSMiddleware":
        if _is_true(keywords.get("allow_credentials")) and (
            _is_wildcard(keywords.get("allow_origins"))
            or (isinstance(keywords.get("allow_origin_regex"), ast.Constant) and keywords["allow_origin_regex"].value in {".*", "^.*$", ".+"})
        ):
            add("CORS-001", node, function, "CORSMiddleware(allow_origins=['*'], allow_credentials=True)")


def _settings_patterns(assignments: dict[str, ast.Assign], add) -> None:
    allow_all = next(
        (
            assignments[name]
            for name in ("CORS_ALLOW_ALL_ORIGINS", "CORS_ORIGIN_ALLOW_ALL")
            if name in assignments and _is_true(assignments[name].value)
        ),
        None,
    )
    credentials = assignments.get("CORS_ALLOW_CREDENTIALS")
    if allow_all is not None and credentials is not None and _is_true(credentials.value):
        add("CORS-001", allow_all, None, "django-cors-headers allows all origins with credentials")


def _random_call(module: Module, node: ast.AST) -> ast.Call | None:
    for child in ast.walk(node):
        if isinstance(child, ast.Call) and _canonical(module, child.func) in _RANDOM_CALLS:
            return child
    return None


def _target_name(target: ast.AST) -> str:
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        return target.attr
    if isinstance(target, ast.Subscript) and isinstance(target.slice, ast.Constant) and isinstance(target.slice.value, str):
        return target.slice.value
    return ""


def _constant_text(node: ast.AST) -> str:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else ""


def _is_true(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _is_false(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def _is_wildcard(node: ast.AST | None) -> bool:
    if isinstance(node, ast.Constant):
        return node.value == "*"
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return any(isinstance(item, ast.Constant) and item.value == "*" for item in node.elts)
    return False


def _redacted(module: Module, node: ast.AST) -> str:
    code = _code(module, node)
    return re.sub(r"""(["'])([^"']{2})[^"']*\1""", r"\1\2<redacted>\1", code)
