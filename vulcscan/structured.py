"""Source-to-sink analysis for PHP, Java, C#, Go, Ruby, C/C++, Shell, PowerShell and Batch.

The engine splits a file into logical statements (multi-line calls included),
keeps one scope per function or method, and follows variables through
assignments, concatenation and string interpolation within a function. It has
no type system and no inter-procedural analysis, so findings that rely on a
variable chain get MEDIUM confidence; a source written directly inside the sink
call keeps the confidence of its source.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from collections.abc import Iterator
from typing import Any, Protocol, cast

from .dataflow import (
    ALL_SINKS,
    COMMAND,
    ENVIRONMENT,
    FILESYSTEM,
    HTML_OUTPUT,
    HTTP_REQUEST,
    LOCAL,
    NORMALIZED,
    REMOTE,
    SQL,
    UNKNOWN,
    Value,
    concatenate,
    constant,
    has_fixed_host,
    judge,
    merge,
    sanitize,
    source_value,
    unique_steps,
    weakest,
    with_step,
)
from .models import Confidence, Finding, FlowStep, Location
from .patches import structured_suggestion
from .regex_safety import safe_for
from .rules import remediations_for, rule
from .source import (
    LineIndex,
    blank_comments,
    code_mask,
    comment_style,
    matching_paren,
    split_arguments,
)

# Argument selectors
FIRST, SECOND, THIRD, LAST, ALL, AFTER_FIRST, REST, TOKEN = "first", "second", "third", "last", "all", "after_first", "rest", "token"


@dataclass(frozen=True, slots=True)
class Sink:
    pattern: re.Pattern[str]
    family: str
    label: str
    argument: str = FIRST
    certainty: Confidence = Confidence.HIGH
    # The statement must also match this pattern (on the comment-free text).
    requires: re.Pattern[str] | None = None
    # Program-path sinks (exec without a shell) skip when the program is constant
    # and the remaining arguments carry the data.
    multi_argument_safe: bool = False


class _Finder(Protocol):
    def finditer(self, text: str, /) -> Iterator[Any]: ...


_SHELL_READ = re.compile(r"\bread\b")
_SHELL_READ_OPTION = re.compile(r"\s++-(?:[A-Za-z]{0,8}[dinNptu]\s++\S++|\w++)")
_SHELL_READ_TARGET = re.compile(r"\s++([A-Za-z_]\w*)")


@dataclass(frozen=True, slots=True)
class _SpanMatch:
    """Minimal ``re.Match`` stand-in: overall span plus one captured name."""

    first: int
    last: int
    target: str
    target_first: int = -1
    target_last: int = -1

    def start(self, index: int = 0) -> int:
        return self.first if index == 0 else self.target_first

    def end(self, index: int = 0) -> int:
        return self.last if index == 0 else self.target_last

    def group(self, *_: int) -> str:
        return self.target


class _ShellRead:
    """``read [options] NAME``: skips option flags (with their arguments), then captures the variable."""

    @staticmethod
    def finditer(text: str) -> Iterator[_SpanMatch]:
        position = 0
        while (keyword := _SHELL_READ.search(text, position)) is not None:
            position = keyword.end()
            while (option := _SHELL_READ_OPTION.match(text, position)) is not None:
                position = option.end()
            target = _SHELL_READ_TARGET.match(text, position)
            if target is None:
                position = keyword.end()
                continue
            position = target.end()
            yield _SpanMatch(keyword.start(), position, target.group(1))


@dataclass(frozen=True, slots=True)
class Catalog:
    prefix: str
    sources: tuple[tuple[re.Pattern[str], int, str], ...]
    sinks: tuple[Sink, ...]
    variables: str  # "dollar", "bare", "percent"
    braces: bool
    assignment: re.Pattern[str]
    sanitizers: tuple[tuple[re.Pattern[str], frozenset[str]], ...] = ()
    normalizers: re.Pattern[str] | None = None
    inputs: tuple[tuple[_Finder, int, str], ...] = ()  # statements that fill a variable
    parameters: _Finder | None = None  # framework-bound handler parameters
    interpolation: re.Pattern[str] | None = None
    function_header: re.Pattern[str] | None = None
    concat: str = "+"


def _sink(pattern: str, family: str, label: str, argument: str = FIRST, *, certainty: Confidence = Confidence.HIGH, requires: str | None = None, multi_argument_safe: bool = False) -> Sink:
    return Sink(
        re.compile(pattern),
        family,
        label,
        argument,
        certainty,
        re.compile(requires) if requires else None,
        multi_argument_safe,
    )


def _sources(*items: tuple[str, int, str]) -> tuple[tuple[re.Pattern[str], int, str], ...]:
    return tuple((re.compile(pattern), trust, description) for pattern, trust, description in items)


_ENV_VARIABLE = "environment variable"
_RAW_SQL = "raw SQL query"
_FILESYSTEM_API = "filesystem API"
_SYSTEM_IO = "System.IO file access"
_NUMERIC = frozenset(ALL_SINKS)
_JAVA_BOXED_PARSE = (
    r"\b(?:Integer|Long|Short|Double|Float|Boolean)\s*\.\s*"
    r"(?:parseInt|parseLong|parseShort|parseDouble|parseFloat|parseBoolean|valueOf)\s*\("
)
_JAVA_UUID_PARSE = r"\bUUID\s*\.\s*fromString\s*\("
_JAVA_NUMERIC_PARSE = re.compile(f"{_JAVA_BOXED_PARSE}|{_JAVA_UUID_PARSE}")
_JAVA_BINDING_ANNOTATIONS = (
    "RequestParam|PathVariable|RequestBody|RequestHeader|RequestPart|CookieValue|QueryParam|"
    "PathParam|HeaderParam|FormParam|CookieParam|MatrixParam|RestQuery|RestPath"
)
_JAVA_PARAMETERS = re.compile(
    rf"@(?:{_JAVA_BINDING_ANNOTATIONS})\b(?:\s*+\([^)]*\))?\s++(?:final\s++)?[\w<>\[\],.? ]+?\s++(\w++)\s*+(?=[,)])"
)
_CS_PARSE_METHODS = r"\b(?:int|long|short|double|float|decimal|bool|Guid)\s*\.\s*(?:Parse|TryParse)\s*\("
_CS_CONVERT_METHODS = r"\bConvert\s*\.\s*To(?:Int\d+|Double|Decimal|Boolean)\s*\("
_CS_NUMERIC_PARSE = re.compile(f"{_CS_PARSE_METHODS}|{_CS_CONVERT_METHODS}")
_CS_ATTRIBUTE = re.compile(r"\[(?:FromQuery|FromBody|FromRoute|FromHeader|FromForm)(?:\([^)]*+\))?+\]")
_CS_TYPE_TOKEN = re.compile(r"\s*+([\w<>\[\],.?]++)")
_CS_TYPE_GAP = re.compile(r" ++([\w<>\[\],.?]++)")
_CS_NAME = re.compile(r"\s++(\w++)\s*+(?=[,)=])")
_CS_UNTYPED_NAME = re.compile(r"[^\S ]*+ \s++(\w++)\s*+(?=[,)=])")


class _CsParameters:
    """``[FromX] Type name`` parameters: attribute, then a (possibly spaced) type, then the bound name."""

    @staticmethod
    def finditer(text: str) -> Iterator[_SpanMatch]:
        position = 0
        while (attribute := _CS_ATTRIBUTE.search(text, position)) is not None:
            name = _CsParameters._name(text, attribute.end())
            if name is None:
                position = attribute.start() + 1
                continue
            position = name.end()
            yield _SpanMatch(attribute.start(), position, name.group(1), name.start(1), name.end(1))

    @staticmethod
    def _name(text: str, position: int) -> re.Match[str] | None:
        token = _CS_TYPE_TOKEN.match(text, position)
        while token is not None:
            name = _CS_NAME.match(text, token.end())
            if name is not None:
                return name
            token = _CS_TYPE_GAP.match(text, token.end())
        return _CS_UNTYPED_NAME.match(text, position)


_CS_PARAMETERS = _CsParameters()
_GO_EXTRA_NAMES = r"(?:\s*,\s*[A-Za-z_]\w*)*"
_GO_TYPE = r"(?:\s+[A-Za-z_][\w.\[\]*]*)?"
_GO_ASSIGNMENT = re.compile(
    rf"^\s*(?:var\s+)?(?P<name>[A-Za-z_]\w*){_GO_EXTRA_NAMES}{_GO_TYPE}\s*(?P<op>:=|=|\+=)(?!=)\s*(?P<value>\S.*)$",
    re.DOTALL,
)
_SHELL_DECLARATION = r"(?:(?:local|export|readonly)\s+|declare\s+(?:-\w+\s+)*)"
_SHELL_ASSIGNMENT = re.compile(rf"^\s*{_SHELL_DECLARATION}?(?P<name>[A-Za-z_]\w*)(?P<op>\+?=)(?P<value>.*)$")
_GUARD_EXIT_WORD = r"\b(?:return|throw|die|exit|abort|raise|halt|head\s*(?::\s*)?(?:\(\s*)?:?(?:bad_request|forbidden|not_found))\b"
_GUARD_EXIT = re.compile(f"{_GUARD_EXIT_WORD}|http\\s*\\.\\s*Error\\s*\\(|panic\\s*\\(")
_FORMAT_CALLS = (
    re.compile(r"\bString\s*\.\s*format\s*\(|\bstring\s*\.\s*Format\s*\("),
    re.compile(r"\bfmt\s*\.\s*Sprintf\s*\(|\bsprintf\s*\("),
)
_CHECK_VARIABLE = r"\$?[A-Za-z_][\w.]*"
_CHECK_LITERAL_LIST = r"(?:\[[^\]]*\]|array\s*\([^)]*\)|%w[\[(][^\])]*[\])]|(?:List|Set|Arrays)\s*\.\s*(?:of|asList)\s*\([^)]*\)|new\s*\[\]\s*\{[^}]*\})"
_IN_ARRAY_CHECK = re.compile(rf"\bin_array\s*\(\s*({_CHECK_VARIABLE})\s*,\s*({_CHECK_LITERAL_LIST}|{_CHECK_VARIABLE})")
_CONTAINS_CHECK = re.compile(
    rf"({_CHECK_LITERAL_LIST}|[A-Z_][A-Z0-9_]*|\w*[Aa]llow\w*)\s*\.\s*(?:contains|Contains|include\?|includes|has|ContainsKey|containsKey)\s*\(?\s*({_CHECK_VARIABLE})"
)
_MATCHES_CHECK = re.compile(rf"({_CHECK_VARIABLE})\s*\.\s*matches\s*\(\s*\"((?:\\.|[^\"\\])*)\"")
_PREG_MATCH_CHECK = re.compile(r"""\bpreg_match\s*\(\s*(['"])(.)\^(.*)\$\2D?([a-zA-Z]*)\1\s*,\s*\$([A-Za-z_]\w*)""")
_RUBY_MATCH_CHECK = re.compile(rf"({_CHECK_VARIABLE})\s*(?:=~|\.match\??)\s*\(?\s*/\\A(.*)\\z/")
_GO_MATCH_CHECK = re.compile(r"""MustCompile\s*\(\s*[`"]\^(.*)\$[`"]\s*\)\s*\.\s*MatchString\s*\(\s*([A-Za-z_]\w*)""")
_PREFIX_CHECK = re.compile(
    rf"({_CHECK_VARIABLE})\s*\.\s*(?:startsWith|StartsWith|start_with\?)\s*\(|(?:strings\s*\.\s*HasPrefix|str_starts_with|strpos)\s*\(\s*({_CHECK_VARIABLE})"
)
_C_ASSIGNMENT = re.compile(
    r"^\s*(?:(?:final|const|static|var|let|auto|readonly|volatile|unsigned|signed|register)\s+)*"
    r"(?P<type>[A-Za-z_][\w:<>,.?\[\]*&]*\s+[*&]*)?(?P<name>[A-Za-z_]\w*)\s*(?P<op>\+?=)(?!=)\s*(?P<value>.+?);?\s*$",
    re.DOTALL,
)

CATALOGS: dict[str, Catalog] = {
    "PHP": Catalog(
        "PHP",
        _sources(
            (r"\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\b", REMOTE, "PHP request superglobal"),
            (r"\bfilter_input\s*\(", REMOTE, "filter_input()"),
            (r"\$request\s*->\s*(?:input|query|get|post|cookie|header|all|file|route|json)\s*\(", REMOTE, "Laravel request input"),
            (r"\$request\s*->\s*(?:query|request|cookies|headers|files|attributes)\s*->\s*(?:get|all)\s*\(", REMOTE, "Symfony request input"),
            (r"\$this\s*->\s*(?:input|request)\s*->\s*(?:get|post|getPost|getGet|cookie|getHeaderLine|getServer|uri)\s*\(", REMOTE, "framework request input"),
            (r"\$request\s*->\s*(?:getQueryParams|getParsedBody|getUploadedFiles|getCookieParams|getHeaderLine|getAttribute)\s*\(", REMOTE, "PSR-7 request input"),
            (r"""\bfile_get_contents\s*\(\s*['"]php://input""", REMOTE, "raw request body"),
            (r"\bgetenv\s*\(|\$_ENV\b", ENVIRONMENT, _ENV_VARIABLE),
            (r"\$argv\b", LOCAL, "command-line argument"),
        ),
        (
            _sink(r"(?<![\w>$:\\])(?:shell_exec|system|exec|passthru|popen|proc_open|pcntl_exec)\s*\(", "CMD", "PHP command execution"),
            _sink(r"->\s*(?:query|exec|prepare|unprepared|statement|raw|whereRaw|orderByRaw|selectRaw|havingRaw|groupByRaw)\s*\(", "SQL", _RAW_SQL),
            _sink(r"->\s*(?:createQuery|createNativeQuery|createSQLQuery)\s*\(", "SQL", "ORM query text"),
            _sink(r"\bDB::(?:raw|select|statement|unprepared)\s*\(", "SQL", _RAW_SQL),
            _sink(r"(?<![\w>$:\\])(?:mysqli_query|mysql_query|pg_query|sqlite_query|mysqli_multi_query)\s*\(", "SQL", "SQL query function", LAST),
            _sink(r"(?<![\w>$:\\])(?:eval|create_function)\s*\(", "CODE", "PHP code evaluation", LAST),
            _sink(r"(?<![\w>$:\\])(?:fopen|file_get_contents|file_put_contents|unlink|readfile|file|rmdir|mkdir|opendir|scandir|highlight_file|show_source)\s*\(", "PATH", _FILESYSTEM_API),
            _sink(r"(?<![\w>$:\\])(?:copy|rename|symlink)\s*\(", "PATH", _FILESYSTEM_API, ALL),
            _sink(r"(?<![\w>$:\\])move_uploaded_file\s*\(", "PATH", "upload destination", SECOND),
            _sink(r"(?<![\w>$:\\])(?:include|include_once|require|require_once)\b\s*\(?", "PATH", "file inclusion", REST),
            _sink(r"(?<![\w>$:\\])unserialize\s*\(", "DESER", "unserialize"),
            _sink(r"(?<![\w>$:\\])curl_init\s*\(", "SSRF", "curl_init"),
            _sink(r"(?<![\w>$:\\])curl_setopt\s*\(", "SSRF", "CURLOPT_URL", THIRD, requires=r"CURLOPT_URL"),
            _sink(r"(?<![\w>$:\\])(?:file_get_contents|fopen|readfile)\s*\(", "SSRF", "PHP URL stream wrapper"),
        ),
        "dollar",
        True,
        re.compile(r"^\s*\$(?P<name>[A-Za-z_]\w*)\s*(?P<op>\.?=)(?!=)\s*(?P<value>\S.*(?=;$)|\S.*);?$", re.DOTALL),
        sanitizers=(
            (re.compile(r"(?<![\w>$])(?:intval|floatval|boolval|abs)\s*\(|\(\s*(?:int|float|bool)\s*\)"), _NUMERIC),
            (re.compile(r"(?<![\w>$])escapeshellarg\s*\("), frozenset({COMMAND})),
            (re.compile(r"(?<![\w>$])basename\s*\("), frozenset({FILESYSTEM})),
            (re.compile(r"(?<![\w>$])(?:md5|sha1|hash)\s*\("), frozenset({FILESYSTEM})),
            (re.compile(r"->\s*quote\s*\(|(?<![\w>$])(?:mysqli_real_escape_string|pg_escape_literal|pg_escape_string)\s*\("), frozenset({SQL})),
        ),
        normalizers=re.compile(r"(?<![\w>$])realpath\s*\("),
        parameters=None,
        interpolation=re.compile(r"\$\{?([A-Za-z_]\w*)"),
        function_header=re.compile(r"\bfunction\s++(?:&\s*+)?\w*+\s*+\("),
        concat=".",
    ),
    "Java": Catalog(
        "JAVA",
        _sources(
            (r"\b\w*[Rr]equest\s*\.\s*(?:getParameter|getParameterValues|getParameterMap|getHeader|getHeaders|getCookies|getQueryString|getRequestURI|getRequestURL|getInputStream|getReader|getPathInfo|getPart)\s*\(", REMOTE, "servlet request input"),
            (r"\b\w*[Rr]equest\s*\.\s*(?:queryParam|pathVariable|header|cookie|body)\s*\(", REMOTE, "reactive request input"),
            (r"\bSystem\s*\.\s*getenv\s*\(", ENVIRONMENT, _ENV_VARIABLE),
            (r"\bSystem\s*\.\s*console\s*\(\s*\)\s*\.\s*readLine\s*\(", LOCAL, "console input"),
        ),
        (
            _sink(r"\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(", "CMD", "Runtime.exec", FIRST),
            _sink(r"\bnew\s+ProcessBuilder\s*\(", "CMD", "ProcessBuilder", FIRST, multi_argument_safe=True),
            _sink(r"\.\s*(?:executeQuery|executeUpdate|executeLargeUpdate|addBatch|prepareStatement|prepareCall|createQuery|createNativeQuery|createSQLQuery)\s*\(", "SQL", "JDBC/JPA query"),
            _sink(r"\b\w*(?:[Ss]tatement|[Ss]tmt|[Jj]dbc[Tt]emplate)\s*\.\s*(?:execute|query|queryForObject|queryForList|queryForMap|update|batchUpdate)\s*\(", "SQL", "SQL execution"),
            _sink(r"\.\s*parseExpression\s*\(", "CODE", "expression language evaluation"),
            _sink(r"\b\w*[Ee]ngine\s*\.\s*eval\s*\(", "CODE", "ScriptEngine.eval"),
            _sink(r"\bnew\s+(?:File|FileInputStream|FileOutputStream|FileReader|FileWriter|RandomAccessFile)\s*\(", "PATH", "java.io file access", ALL),
            _sink(r"\b(?:Paths\s*\.\s*get|Path\s*\.\s*of)\s*\(", "PATH", "java.nio path", ALL),
            _sink(r"\bFiles\s*\.\s*(?:readString|readAllBytes|readAllLines|write|writeString|delete|deleteIfExists|newInputStream|newOutputStream|copy|move|lines|newBufferedReader|newBufferedWriter)\s*\(", "PATH", "java.nio.file.Files"),
            _sink(r"\bnew\s+(?:ObjectInputStream|XMLDecoder)\s*\(", "DESER", "Java native deserialization"),
            _sink(r"\b(?:new\s+URL|URI\s*\.\s*create|HttpRequest\s*\.\s*newBuilder)\s*\(", "SSRF", "outbound URL"),
            _sink(r"\b\w*[Rr]est[Tt]emplate\s*\.\s*(?:getForObject|getForEntity|postForObject|postForEntity|exchange)\s*\(", "SSRF", "RestTemplate request"),
            _sink(r"\b\w*[Rr]esponse\s*\.\s*getWriter\s*\(\s*\)\s*\.\s*(?:print|println|printf|write)\s*\(", "XSS", "servlet response writer", ALL),
        ),
        "bare",
        True,
        _C_ASSIGNMENT,
        sanitizers=(
            (_JAVA_NUMERIC_PARSE, _NUMERIC),
            (re.compile(r"\bFilenameUtils\s*\.\s*getName\s*\(|\.\s*getFileName\s*\(\s*\)"), frozenset({FILESYSTEM})),
            (re.compile(r"\b(?:Encode\s*\.\s*forHtml|HtmlUtils\s*\.\s*htmlEscape|StringEscapeUtils\s*\.\s*escapeHtml4)\s*\("), frozenset({HTML_OUTPUT})),
        ),
        normalizers=re.compile(r"\.\s*(?:normalize|toRealPath|getCanonicalPath|getCanonicalFile)\s*\("),
        parameters=_JAVA_PARAMETERS,
        function_header=re.compile(r"(?:public|private|protected|static|final|synchronized|abstract)?[\w<>\[\],.? ]*\s(\w+)\s*\($"),
    ),
    "C#": Catalog(
        "CS",
        _sources(
            (r"\b(?:HttpContext\s*\.\s*)?Request\s*\.\s*(?:Query|Form|Headers|Cookies|RouteValues|Body|QueryString|Path)\b", REMOTE, "ASP.NET request input"),
            (r"\bEnvironment\s*\.\s*GetEnvironmentVariable\s*\(", ENVIRONMENT, _ENV_VARIABLE),
            (r"\bConsole\s*\.\s*ReadLine\s*\(", LOCAL, "console input"),
        ),
        (
            _sink(r"\bProcess\s*\.\s*Start\s*\(", "CMD", "Process.Start", FIRST, multi_argument_safe=True),
            _sink(r"\bnew\s+ProcessStartInfo\s*\(", "CMD", "ProcessStartInfo", FIRST, multi_argument_safe=True),
            _sink(r"\bnew\s+(?:SqlCommand|SqliteCommand|NpgsqlCommand|MySqlCommand|OleDbCommand|OdbcCommand|OracleCommand)\s*\(", "SQL", "ADO.NET command"),
            _sink(r"\.\s*(?:FromSqlRaw|ExecuteSqlRaw|ExecuteSqlRawAsync|SqlQueryRaw)\s*\(", "SQL", "EF Core raw SQL"),
            _sink(r"\b\w*(?:[Cc]onn(?:ection)?|[Dd]b)\s*\.\s*(?:Query|QueryAsync|QueryFirst\w*|QuerySingle\w*|Execute|ExecuteAsync|ExecuteScalar\w*)\s*(?:<[^>()]*>)?\s*\(", "SQL", "Dapper query"),
            _sink(r"\.\s*CommandText\s*=", "SQL", "CommandText", REST),
            _sink(r"\bCSharpScript\s*\.\s*(?:EvaluateAsync|RunAsync|Create)\s*(?:<[^>()]*>)?\s*\(", "CODE", "C# scripting"),
            _sink(r"\bAssembly\s*\.\s*(?:Load|LoadFrom|LoadFile)\s*\(", "CODE", "dynamic assembly load"),
            _sink(r"\b(?:File|Directory)\s*\.\s*(?:ReadAllText|ReadAllBytes|ReadAllLines|ReadLines|WriteAllText|WriteAllBytes|AppendAllText|Delete|Open|OpenRead|OpenWrite|Create|CreateDirectory|GetFiles|EnumerateFiles)\s*\(", "PATH", _SYSTEM_IO),
            _sink(r"\b(?:File|Directory)\s*\.\s*(?:Copy|Move)\s*\(", "PATH", _SYSTEM_IO, ALL),
            _sink(r"\bnew\s+(?:FileStream|StreamReader|StreamWriter|FileInfo|DirectoryInfo)\s*\(", "PATH", _SYSTEM_IO),
            _sink(r"\bPhysicalFile\s*\(", "PATH", "PhysicalFile result"),
            _sink(r"\b(?:new\s+(?:BinaryFormatter|SoapFormatter|LosFormatter|NetDataContractSerializer|ObjectStateFormatter)\s*\(\s*\)|\w*[Ff]ormatter)\s*\.\s*Deserialize\s*\(", "DESER", "native .NET deserialization", requires=r"\b(?:BinaryFormatter|SoapFormatter|LosFormatter|NetDataContractSerializer|ObjectStateFormatter)\b"),
            _sink(r"\b\w*(?:[Cc]lient|[Hh]ttp)\w*\s*\.\s*(?:GetAsync|PostAsync|PutAsync|DeleteAsync|GetStringAsync|GetStreamAsync|GetByteArrayAsync|GetFromJsonAsync)\s*\(", "SSRF", "HttpClient request"),
            _sink(r"\bWebRequest\s*\.\s*Create(?:Http)?\s*\(", "SSRF", "WebRequest.Create"),
            _sink(r"\b(?:Response\s*\.\s*)?Write(?:Async)?\s*\(", "XSS", "HTTP response writer"),
            _sink(r"\bHtml\s*\.\s*Raw\s*\(", "XSS", "Html.Raw"),
        ),
        "bare",
        True,
        _C_ASSIGNMENT,
        sanitizers=(
            (_CS_NUMERIC_PARSE, _NUMERIC),
            (re.compile(r"\bPath\s*\.\s*GetFileName\s*\("), frozenset({FILESYSTEM})),
            (re.compile(r"\b(?:HtmlEncoder\s*\.\s*Default\s*\.\s*Encode|HttpUtility\s*\.\s*HtmlEncode)\s*\("), frozenset({HTML_OUTPUT})),
        ),
        normalizers=re.compile(r"\bPath\s*\.\s*GetFullPath\s*\("),
        parameters=_CS_PARAMETERS,
        interpolation=re.compile(r"\{([A-Za-z_][\w.]*)"),
        function_header=re.compile(r"(?:public|private|protected|internal|static|async|override|virtual)[\w<>\[\],.? ]*\s(\w+)\s*\($"),
    ),
    "Go": Catalog(
        "GO",
        _sources(
            (r"\b\w+\s*\.\s*URL\s*\.\s*Query\s*\(\s*\)(?:\s*\.\s*Get\s*\()?|\b\w+\s*\.\s*(?:FormValue|PostFormValue|PathValue)\s*\(|\b\w+\s*\.\s*Header\s*\.\s*Get\s*\(|\b\w+\s*\.\s*URL\s*\.\s*(?:Path|RawQuery)\b", REMOTE, "net/http request input"),
            (r"\b(?:c|ctx|context)\s*\.\s*(?:Query|Queries|DefaultQuery|Param|Params|PostForm|DefaultPostForm|FormValue|FormFile|GetHeader|GetReqHeaders|Cookie|Cookies|QueryParam|FormParams|PathParam|Body|BodyRaw)\s*\(", REMOTE, "web framework request input"),
            (r"\bos\s*\.\s*Getenv\s*\(", ENVIRONMENT, _ENV_VARIABLE),
            (r"\bos\s*\.\s*Args\b|\bflag\s*\.\s*(?:Arg|Args)\s*\(", LOCAL, "command-line argument"),
        ),
        (
            _sink(r"\bexec\s*\.\s*Command\s*\(", "CMD", "exec.Command", FIRST, multi_argument_safe=True),
            _sink(r"\bexec\s*\.\s*CommandContext\s*\(", "CMD", "exec.CommandContext", SECOND, multi_argument_safe=True),
            _sink(r"\b\w*(?:[Dd][Bb]|[Tt]x|[Cc]onn|[Ss]tmt)\s*\.\s*(?:Query|QueryRow|Exec|Prepare|Queryx|QueryRowx|MustExec|Raw)\s*\(", "SQL", "database query"),
            _sink(r"\b\w*(?:[Dd][Bb]|[Tt]x|[Cc]onn)\s*\.\s*(?:QueryContext|QueryRowContext|ExecContext|PrepareContext|Select|Get)\s*\(", "SQL", "database/sql query", SECOND),
            _sink(r"\b\w*(?:[Dd][Bb]|[Tt]x)\s*\.\s*(?:Where|Not|Or|Order|Select|Table|Joins|Group|Having)\s*\(", "SQL", "ORM SQL fragment", certainty=Confidence.MEDIUM),
            _sink(r"\b(?:os\s*\.\s*(?:Open|OpenFile|Create|Remove|RemoveAll|ReadFile|WriteFile|Mkdir|MkdirAll|ReadDir)|ioutil\s*\.\s*(?:ReadFile|WriteFile))\s*\(", "PATH", "os file access"),
            _sink(r"\bhttp\s*\.\s*ServeFile\s*\(", "PATH", "http.ServeFile", THIRD),
            _sink(r"\bhttp\s*\.\s*(?:Get|Post|Head|PostForm)\s*\(", "SSRF", "net/http request"),
            _sink(r"\bhttp\s*\.\s*NewRequest\s*\(", "SSRF", "http.NewRequest", SECOND),
            _sink(r"\bhttp\s*\.\s*NewRequestWithContext\s*\(", "SSRF", "http.NewRequestWithContext", THIRD),
            _sink(r"\bfmt\s*\.\s*Fprint(?:f|ln)?\s*\(", "XSS", "HTTP response writer", AFTER_FIRST, requires=r"\bfmt\s*\.\s*Fprint(?:f|ln)?\s*\(\s*(?:w|writer|c\s*\.\s*Writer|ctx\s*\.\s*Writer)\s*,"),
            _sink(r"\btemplate\s*\.\s*HTML\s*\(", "XSS", "template.HTML trust bypass"),
        ),
        "bare",
        True,
        _GO_ASSIGNMENT,
        sanitizers=(
            (re.compile(r"\bstrconv\s*\.\s*(?:Atoi|ParseInt|ParseUint|ParseFloat|ParseBool)\s*\(|\buuid\s*\.\s*Parse\s*\("), _NUMERIC),
            (re.compile(r"\bfilepath\s*\.\s*Base\s*\("), frozenset({FILESYSTEM})),
            (re.compile(r"\bhtml\s*\.\s*EscapeString\s*\("), frozenset({HTML_OUTPUT})),
        ),
        normalizers=re.compile(r"\bfilepath\s*\.\s*(?:Clean|Abs|Join)\s*\("),
        function_header=re.compile(r"\bfunc\b"),
    ),
    "Ruby": Catalog(
        "RB",
        _sources(
            (r"\bparams\s*(?:\[|\.)|\bcookies\s*\[|\brequest\s*\.\s*(?:headers|body|params|query_string|path|url|raw_post)\b", REMOTE, "Rails/Rack request input"),
            (r"\bENV\s*(?:\[|\.\s*fetch)", ENVIRONMENT, _ENV_VARIABLE),
            (r"\bARGV\b|(?<![\w.])gets\b|\$stdin\b|\bSTDIN\b", LOCAL, "command-line or stdin input"),
        ),
        (
            _sink(r"(?<![\w.:])(?:system|exec|spawn)\b\s*\(?", "CMD", "Kernel command execution", FIRST, multi_argument_safe=True),
            _sink(r"\b(?:IO\s*\.\s*popen|Open3\s*\.\s*(?:capture2e?|capture3|popen[23]e?))\s*\(", "CMD", "process spawn", FIRST, multi_argument_safe=True),
            _sink(r"`[^`]*#\{|%x[\(\[{]", "CMD", "backtick command", REST),
            _sink(r"(?<![\w.:])(?:Kernel\s*\.\s*)?open\s*\(", "CMD", "Kernel#open"),
            _sink(r"\.\s*(?:find_by_sql|execute|exec_query|select_all|select_value|select_rows|count_by_sql)\b\s*\(?", "SQL", _RAW_SQL),
            _sink(r"\.\s*(?:where|having|joins|from|lock)\s*\(\s*(?=[\"'%])", "SQL", "ActiveRecord string condition"),
            _sink(r"\.\s*(?:order|reorder|group|pluck)\s*\(", "SQL", "ActiveRecord order/group clause", certainty=Confidence.MEDIUM),
            _sink(r"(?<![\w.:])(?:eval|instance_eval|class_eval|module_eval)\b\s*\(?", "CODE", "Ruby evaluation"),
            _sink(r"\.\s*(?:send|public_send|constantize)\b\s*\(?", "CODE", "dynamic method dispatch", certainty=Confidence.MEDIUM),
            _sink(r"\b(?:File|IO)\s*\.\s*(?:read|write|open|delete|unlink|readlines|binread|foreach|new)\s*\(", "PATH", "File access"),
            _sink(r"\bFileUtils\s*\.\s*(?:rm|rm_rf|rm_r|cp|mv|mkdir_p|touch)\s*\(", "PATH", "FileUtils"),
            _sink(r"(?<![\w.:])send_file\b\s*\(?", "PATH", "send_file"),
            _sink(r"\bMarshal\s*\.\s*(?:load|restore)\s*\(", "DESER", "Marshal.load"),
            _sink(r"\b(?:YAML|Psych)\s*\.\s*unsafe_load\s*\(", "DESER", "YAML.unsafe_load"),
            _sink(r"\b(?:YAML|Psych)\s*\.\s*load\s*\(", "DESER", "YAML.load (unsafe before Psych 4)", certainty=Confidence.MEDIUM),
            _sink(r"\b(?:URI\s*\.\s*open|Net::HTTP\s*\.\s*(?:get|get_response|post_form)|HTTParty\s*\.\s*(?:get|post)|Faraday\s*\.\s*(?:get|post)|RestClient\s*\.\s*(?:get|post))\s*\(", "SSRF", "outbound HTTP request"),
            _sink(r"(?<![\w.:])raw\s*\(", "XSS", "Rails raw HTML"),
            _sink(r"(?<![\w.:])render\s+html\s*:\s*", "XSS", "Rails HTML response", REST),
        ),
        "bare",
        False,
        re.compile(r"^\s*(?P<name>@{0,2}[A-Za-z_]\w*)\s*(?P<op>\+?=|\|\|=)(?![=~])\s*(?P<value>\S.*)$", re.DOTALL),
        sanitizers=(
            (re.compile(r"\b(?:Integer|Float)\s*\(|\.\s*to_[if]\b"), _NUMERIC),
            (re.compile(r"\bShellwords\s*\.\s*(?:escape|shellescape)\s*\(|\.\s*shellescape\b"), frozenset({COMMAND})),
            (re.compile(r"\bFile\s*\.\s*basename\s*\("), frozenset({FILESYSTEM})),
            (re.compile(r"\b(?:sanitize_sql\w*|quote)\s*\("), frozenset({SQL})),
            (re.compile(r"\b(?:ERB::Util\s*\.\s*html_escape|CGI\s*\.\s*escapeHTML)\s*\("), frozenset({HTML_OUTPUT})),
        ),
        normalizers=re.compile(r"\bFile\s*\.\s*(?:expand_path|realpath)\s*\("),
        interpolation=re.compile(r"#\{([^}]*)\}"),
    ),
    "C": Catalog(
        "C",
        _sources(
            (r"\bargv\s*\[|(?<![\w.])gets\s*\(|\bstd::cin\b", LOCAL, "command-line or stdin input"),
            (r"\bgetenv\s*\(", ENVIRONMENT, _ENV_VARIABLE),
        ),
        (
            _sink(r"(?<![\w.>:])(?:system|popen|_popen|_wsystem)\s*\(", "CMD", "C command execution"),
            _sink(r"(?<![\w.>:])exec(?:l|lp|le|v|vp|vpe|ve)\s*\(", "CMD", "exec family program path"),
            _sink(r"\b(?:sqlite3_exec|sqlite3_prepare(?:_v2|_v3)?|mysql_query|mysql_real_query|PQexec)\s*\(", "SQL", "database query", SECOND),
            _sink(r"(?<![\w.>:])(?:fopen|open|remove|unlink|rmdir|rename)\s*\(", "PATH", _FILESYSTEM_API),
        ),
        "bare",
        True,
        _C_ASSIGNMENT,
        sanitizers=((re.compile(r"(?<![\w.])(?:atoi|atol|atoll|strtol|strtoul|strtod|std::sto(?:i|l|ul|d))\s*\("), _NUMERIC),),
        normalizers=re.compile(r"(?<![\w.])realpath\s*\("),
        inputs=(
            (re.compile(r"\brecv(?:from)?\s*\(\s*\w+\s*,\s*(\w+)"), REMOTE, "network data from recv()"),
            (re.compile(r"\bfgets\s*\(\s*(\w+)\s*,[^,]+,\s*stdin\s*\)"), LOCAL, "stdin line from fgets()"),
            (re.compile(r"\bscanf\s*\(\s*\"[^\"]*\"\s*,\s*&?(\w+)"), LOCAL, "stdin input from scanf()"),
            (re.compile(r"\bstd::getline\s*\(\s*std::cin\s*,\s*(\w+)"), LOCAL, "stdin line from std::getline()"),
            (re.compile(r"\bstd::cin\s*>>\s*(\w+)"), LOCAL, "stdin input from std::cin"),
        ),
    ),
    "Shell": Catalog(
        "SH",
        _sources((r"\$(?:[1-9@*]|\{[1-9@*]\})", LOCAL, "script argument"),),
        (
            _sink(r"(?:^|[;&|]\s*|\bthen\s+|\bdo\s+)eval\s+", "CODE", "shell eval", REST),
            _sink(r"(?:^|[;&|]\s*)(?:source|\.)\s+(?=\S)", "CODE", "shell source", TOKEN),
            _sink(r"\b(?:sh|bash|dash|zsh|ksh)\s+-c\s+", "CMD", "shell -c", REST),
        ),
        "dollar",
        False,
        _SHELL_ASSIGNMENT,
        inputs=((_ShellRead(), LOCAL, "line read from stdin"),),
    ),
    "PowerShell": Catalog(
        "PS",
        _sources(
            (r"\$Request\s*\.\s*(?:Query|Body|Headers|Params)\b", REMOTE, "Azure Functions request input"),
            (r"\$args\b|\bRead-Host\b", LOCAL, "script argument or console input"),
            (r"\$env:\w+", ENVIRONMENT, _ENV_VARIABLE),
        ),
        (
            _sink(r"\b(?:Invoke-Expression|iex)\b\s+", "CODE", "Invoke-Expression", REST),
            _sink(r"\[ScriptBlock\]::Create\s*\(", "CODE", "ScriptBlock.Create"),
            _sink(r"\bStart-Process\b\s+(?:-FilePath\s+)?", "CMD", "Start-Process", TOKEN),
            _sink(r"(?:^|[;|]\s*)&\s*(?=\$)", "CMD", "call operator", TOKEN),
            _sink(r"\bcmd(?:\.exe)?\s+/[ck]\s+", "CMD", "cmd /c", REST),
            _sink(r"\bInvoke-Sqlcmd\b[^\n]*?-Query\s+", "SQL", "Invoke-Sqlcmd", TOKEN),
            _sink(r"\b(?:Get-Content|Set-Content|Add-Content|Remove-Item|New-Item|Copy-Item|Move-Item|Out-File)\b\s+(?:-(?:Path|LiteralPath|FilePath)\s+)?", "PATH", "filesystem cmdlet", TOKEN),
            _sink(r"\b(?:Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b\s+(?:-Uri\s+)?", "SSRF", "web request", TOKEN),
        ),
        "dollar",
        False,
        re.compile(r"^\s*\$(?P<name>[A-Z_]\w*)\s*(?P<op>\+?=)(?!=)\s*(?P<value>\S.*)$", re.IGNORECASE),
        sanitizers=((re.compile(r"\[(?:int|long|double|guid)\]\s*", re.IGNORECASE), _NUMERIC),),
    ),
    "Batch": Catalog(
        "BAT",
        _sources((r"%~?[1-9*]", LOCAL, "script argument"),),
        (
            _sink(r"(?i)\bcall\s+", "CMD", "call", REST),
            _sink(r"(?i)\bcmd(?:\.exe)?\s+/[ck]\s+", "CMD", "cmd /c", REST),
            _sink(r"(?i)\bpowershell(?:\.exe)?\b[^\n]*?-(?:Command|c)\s+", "CODE", "PowerShell command text", REST),
        ),
        "percent",
        False,
        re.compile(r"(?i)^\s*set\s+\"?(?P<name>[A-Z_]\w*)(?P<op>=)(?P<value>.*(?=\"$)|.*)\"?$"),
        inputs=((re.compile(r"(?i)\bset\s+/p\s+\"?([A-Z_]\w*)\s*="), LOCAL, "console input from set /p"),),
    ),
}
CATALOGS["C++"] = replace(CATALOGS["C"], sinks=(*CATALOGS["C"].sinks, _sink(r"\bstd::(?:ifstream|ofstream|fstream)\s+\w+\s*\(", "PATH", "file stream")))


@dataclass(slots=True)
class _Scope:
    function: bool
    values: dict[str, Value] = field(default_factory=dict)
    name: str | None = None


@dataclass(frozen=True, slots=True)
class _Statement:
    start: int
    end: int
    opens: int = 0
    closes: int = 0


class _Engine:
    def __init__(self, path: str, text: str, language: str, catalog: Catalog) -> None:
        self.path = path
        self.language = language
        self.catalog = catalog
        style = comment_style(language)
        if language == "PHP":
            text = re.sub(r"<\?(?:php\b|=)?|\?>", lambda match: " " * len(match.group(0)), text)
        self.text = blank_comments(text, style)
        self.mask = code_mask(text, style)
        self.index = LineIndex(text)
        self.scopes = [_Scope(function=True)]
        self.findings: list[Finding] = []
        self.pending_parameters: list[tuple[str, Value]] = []
        self.pending_name: str | None = None
        self.pending_guard: list[tuple[str, frozenset[str]]] = []

    def run(self) -> list[Finding]:
        statements = list(self._statements())
        for position, statement in enumerate(statements):
            self._statement(statement, statements[position + 1 :])
        return self.findings

    # Statement splitting ------------------------------------------------------------

    def _statements(self):
        if self.catalog.braces:
            yield from self._brace_statements()
        else:
            yield from self._line_statements()

    def _brace_statements(self):
        mask = self.mask
        paren = 0
        start = 0
        stack: list[tuple[bool, int]] = []  # (is_block, saved paren depth)
        for index, char in enumerate(mask):
            statement: _Statement | None = None
            if char in "([":
                paren += 1
            elif char in ")]":
                paren = max(0, paren - 1)
            elif char == "{":
                statement, paren, start = self._open_brace(index, paren, start, stack)
            elif char == "}":
                statement, paren, start = self._close_brace(index, paren, start, stack)
            elif char == ";" and paren == 0:
                statement = _Statement(start, index)
                start = index + 1
            elif char == "\n" and paren == 0 and self.language == "Go":
                statement = self._go_line_break(index, start)
                if statement is not None:
                    start = index + 1
            if statement is not None:
                yield statement
        yield _Statement(start, len(mask))

    def _open_brace(self, index: int, paren: int, start: int, stack: list[tuple[bool, int]]):
        before = self.mask[start:index].rstrip()
        if paren == 0 or before.endswith((")", "->", "=>")):
            # A block: function body, lambda/closure body or control block.
            stack.append((True, paren))
            return _Statement(start, index, opens=1), 0, index + 1
        stack.append((False, 0))  # composite or array literal
        return None, paren + 1, start

    @staticmethod
    def _close_brace(index: int, paren: int, start: int, stack: list[tuple[bool, int]]):
        if stack and not stack[-1][0]:
            stack.pop()
            return None, max(0, paren - 1), start
        saved = stack.pop()[1] if stack else 0
        return _Statement(start, index, closes=1), saved, index + 1

    def _go_line_break(self, index: int, start: int) -> _Statement | None:
        current = self.mask[start:index].strip()
        if current and not re.search(r"[=+\-*/%&|^!<>,.(]$", current):
            return _Statement(start, index)
        return None


    def _line_statements(self):
        mask = self.mask
        start = 0
        paren = 0
        continuation = {"Shell": "\\", "PowerShell": "`", "Batch": "^"}.get(self.language)
        for index, char in enumerate(mask):
            if char in "([{":
                paren += 1
            elif char in ")]}":
                paren = max(0, paren - 1)
            elif char == "\n":
                if self._continues_line(mask[start:index].rstrip(), paren, continuation):
                    continue
                yield _Statement(start, index)
                start = index + 1
                paren = 0
            elif char == ";" and paren == 0 and self.language in {"Shell", "PowerShell", "Ruby"}:
                yield _Statement(start, index)
                start = index + 1
        yield _Statement(start, len(mask))

    def _continues_line(self, current: str, paren: int, continuation: str | None) -> bool:
        if continuation and current.endswith(continuation):
            return True
        if self.language != "Ruby":
            return False
        return paren > 0 or bool(re.search(r"[,(\[+\\|&.]$", current)) or current.endswith(" \\")


    # Statements -------------------------------------------------------------------

    def _statement(self, statement: _Statement, following: list[_Statement]) -> None:
        start, end = statement.start, statement.end
        if self.mask[start:end].strip():
            self._process(start, end, following, opens=bool(statement.opens))
        if statement.closes:
            self._close()
        if statement.opens:
            self._open()

    def _process(self, start: int, end: int, following: list[_Statement], *, opens: bool) -> None:
        if self.language == "Ruby":
            self._ruby_scopes(start, end)
        if self.catalog.parameters is not None:
            for match in self.catalog.parameters.finditer(self.text[start:end]):
                name = match.group(1)
                step = FlowStep("SOURCE", self._location(start + match.start(1), start + match.end(1)), name, "Framework-bound HTTP parameter.")
                self.pending_parameters.append((name, source_value(step, REMOTE)))
        self._sinks(start, end)
        for pattern, trust, description in self.catalog.inputs:
            for match in pattern.finditer(self.text[start:end]):
                step = FlowStep("SOURCE", self._location(start + match.start(), start + match.end()), _compact(self.text[start:end]), f"{description[0].upper()}{description[1:]}.")
                self._assign(match.group(1), source_value(step, trust), declare=True)
        self._assignment(start, end)
        self._guard(start, end, following)
        header = self._function_header(start, end) if opens else None
        if header is not None:
            self.pending_name, parameters = header
            for name in parameters:
                if name not in {item[0] for item in self.pending_parameters}:
                    self.pending_parameters.append((name, UNKNOWN))

    def _open(self) -> None:
        function = bool(self.pending_parameters) or self.pending_name is not None
        scope = _Scope(function=function, name=self.pending_name or self._enclosing_name())
        for name, value in self.pending_parameters:
            scope.values[name] = value
        self.pending_parameters = []
        self.pending_name = None
        self.scopes.append(scope)

    def _close(self) -> None:
        if len(self.scopes) > 1:
            self.scopes.pop()

    def _ruby_scopes(self, start: int, end: int) -> None:
        code = self.mask[start:end].strip()
        definition = re.match(r"def\s+(?:self\.)?([\w?!=]+)\s*(?:\(([^)]*)\)|([^=]+))?", code)
        if definition:
            scope = _Scope(function=True, name=definition.group(1))
            for name in re.findall(r"([A-Za-z_]\w*)", definition.group(2) or definition.group(3) or ""):
                scope.values[name] = UNKNOWN
            self.scopes.append(scope)
            if re.search(r"\bend\s*$", code) or re.search(r"\)\s*=\s*\S", code):
                self.scopes.pop()  # one-line method
            return
        if re.match(r"(?:class|module|if|unless|while|until|for|case|begin)\b", code) and not re.search(r"\bend\s*$", code):
            self.scopes.append(_Scope(function=False, name=self._enclosing_name()))
            return
        if re.search(r"\bdo(?:\s*\|[^|]*\|)?\s*$", code):
            self.scopes.append(_Scope(function=False, name=self._enclosing_name()))
            return
        if re.match(r"end\b", code) and len(self.scopes) > 1:
            self.scopes.pop()

    def _function_header(self, start: int, end: int) -> tuple[str | None, list[str]] | None:
        code = self.mask[start:end].rstrip()
        if ")" not in code or not self._may_declare_function(code):
            return None
        open_index = self._parameter_list(start, end)
        if open_index < 0:
            return None
        close = matching_paren(self.mask, open_index)
        if close < 0:
            return None
        before = self.mask[start:open_index].rstrip()
        name_match = re.search(r"([A-Za-z_]\w*)$", before)
        if not name_match or name_match.group(1) in {"if", "for", "while", "switch", "catch", "return", "new"}:
            return None
        if self.language not in {"Go", "PHP"} and not re.search(r"[\w>\]?*&]\s+[A-Za-z_]\w*$", before):
            return None  # a call, not a declaration
        parameters = []
        for part_start, part_end in split_arguments(self.mask, open_index + 1, close):
            names = self._parameter_names(self.text[part_start:part_end])
            parameters.extend(names[:1] if self.language == "Go" else names[-1:])
        return name_match.group(1), parameters

    def _may_declare_function(self, code: str) -> bool:
        if self.language == "Go":
            return bool(re.match(r"\s*func\b", code))
        if self.language == "PHP":
            return bool(re.search(r"\bfunction\b", code))
        return not re.match(r"\s*(?:if|for|foreach|while|switch|catch|using|lock|else|return|new|synchronized|try|do)\b", code)

    def _parameter_names(self, part: str) -> list[str]:
        if self.catalog.variables == "dollar":
            return re.findall(r"\$([A-Za-z_]\w*)", part)
        part = re.sub(r"@\w+(?:\([^)]*\))?|\[[^\]]*\]", " ", part).split("=", 1)[0]
        if self.language == "Go":
            return re.findall(r"^\s*([A-Za-z_]\w*)", part)
        return re.findall(r"([A-Za-z_]\w*)\s*$", part.strip())


    def _parameter_list(self, start: int, end: int) -> int:
        """Return the offset of the '(' that opens the parameter list."""
        code = self.mask[start:end]
        if self.language == "Go":
            match = re.match(r"\s*func\s*(?:\([^)]*\)\s*)?[A-Za-z_]\w*\s*(?:\[[^\]]*\]\s*)?\(", code)
            return start + match.end() - 1 if match else -1
        depth = 0
        for index in range(len(code) - 1, -1, -1):
            char = code[index]
            if char == ")":
                depth += 1
            elif char == "(":
                depth -= 1
                if depth == 0:
                    # skip a trailing "throws" clause or return type: we want the
                    # parameter list right after the function name
                    return start + index
        return -1

    def _enclosing_name(self) -> str | None:
        for scope in reversed(self.scopes):
            if scope.function and scope.name:
                return scope.name
        return None

    # Assignments ------------------------------------------------------------------

    def _assignment(self, start: int, end: int) -> None:
        code = self.mask[start:end]
        match = self.catalog.assignment.match(code.rstrip())
        if not match:
            return
        if re.match(r"\s*(?:return|if|while|for|elif|else|unless|until|case|when)\b", code):
            return
        name = match.group("name")
        value_start, value_end = start + match.start("value"), start + match.end("value")
        value = self._value(value_start, value_end)
        operator = match.group("op")
        if operator in {"+=", ".="}:
            value = concatenate([self._lookup(name) or UNKNOWN, value])
        first = start + len(code) - len(code.lstrip())
        step = FlowStep("PROPAGATION", self._location(first, end), _compact(self.text[start:end]), f"Value is assigned to {name}.")
        declared = bool(match.groupdict().get("type")) or operator == ":=" or self.language in {"PHP", "Shell", "PowerShell", "Batch"}
        self._assign(name, with_step(value, step), declare=declared)

    def _assign(self, name: str, value: Value, *, declare: bool) -> None:
        if self.language == "PHP":
            # PHP variables are function-scoped.
            for scope in reversed(self.scopes):
                if scope.function:
                    scope.values[name] = value
                    return
        if not declare and self._reassign(name, value):
            return
        self.scopes[-1].values[name] = value

    def _reassign(self, name: str, value: Value) -> bool:
        for scope in reversed(self.scopes):
            if name in scope.values:
                scope.values[name] = value
                return True
            if scope.function and self.language == "Ruby":
                break
        return False


    def _lookup(self, name: str) -> Value | None:
        for scope in reversed(self.scopes):
            if name in scope.values:
                return scope.values[name]
            if scope.function and self.language in {"Ruby", "PHP"} and scope is not self.scopes[0]:
                return None  # methods do not see outer locals
        return None

    # Guards -----------------------------------------------------------------------

    def _guard(self, start: int, end: int, following: list[_Statement]) -> None:
        """Recognize ``if (!allowed(x)) { return/throw }`` style early exits."""
        text = self.text[start:end]
        condition = re.match(r"\s*(?:if\s*\(?|unless\s+|elsif\s+)(.*)", text, re.DOTALL)
        modifier = re.search(r"\b(?:unless|if)\s++(.++)$", text) if self.language == "Ruby" and _GUARD_EXIT.match(text.strip()) else None
        if not condition and not modifier:
            return
        expression = (modifier or condition).group(1)
        if not self._guard_exits(text, condition, modifier, following):
            return
        negated_keyword = text.lstrip().startswith("unless") or bool(modifier and modifier.group(0).startswith("unless"))
        negated = negated_keyword ^ bool(re.match(r"\s*(?:\(\s*)?(?:!|not\b)", expression))
        if not negated and not re.search(r"(?:===?|!==?)\s*false\b", expression):
            return
        for name, categories in self._checks(expression):
            current = self._lookup(name)
            if current is not None:
                self._assign(name, sanitize(current, categories), declare=False)

    def _guard_exits(self, text: str, condition: re.Match[str] | None, modifier: re.Match[str] | None, following: list[_Statement]) -> bool:
        exits = bool(modifier) or bool(_GUARD_EXIT.search(text[(condition.end(1) if condition else 0):]))
        if exits or not following:
            return exits
        body = self.mask[following[0].start : following[0].end]
        if _GUARD_EXIT.search(body):
            return True
        if len(following) > 1 and not body.strip():
            return bool(_GUARD_EXIT.search(self.mask[following[1].start : following[1].end]))
        return False


    def _checks(self, expression: str) -> list[tuple[str, frozenset[str]]]:
        results: list[tuple[str, frozenset[str]]] = []
        for match in _IN_ARRAY_CHECK.finditer(expression):
            results.append((match.group(1).lstrip("$"), ALL_SINKS))
        for match in _CONTAINS_CHECK.finditer(expression):
            results.append((match.group(2).lstrip("$"), ALL_SINKS))
        for match in _MATCHES_CHECK.finditer(expression):
            self._add_regex_check(results, match.group(1), match.group(2).encode().decode("unicode_escape"))
        for match in _PREG_MATCH_CHECK.finditer(expression):
            if "D" in match.group(0)[-30:] or match.group(4).find("D") >= 0:
                self._add_regex_check(results, match.group(5), match.group(3))
        for match in _RUBY_MATCH_CHECK.finditer(expression):
            self._add_regex_check(results, match.group(1), match.group(2))
        for match in _GO_MATCH_CHECK.finditer(expression):
            self._add_regex_check(results, match.group(2), match.group(1))
        for match in _PREFIX_CHECK.finditer(expression):
            name = (match.group(1) or match.group(2)).lstrip("$")
            current = self._lookup(name)
            if current is not None and NORMALIZED in current.sanitized:
                results.append((name, frozenset({FILESYSTEM})))
        return results

    @staticmethod
    def _add_regex_check(results: list[tuple[str, frozenset[str]]], name: str, regex: str) -> None:
        categories = safe_for(regex, fullmatch=True)
        if categories:
            results.append((name, categories))


    # Values -----------------------------------------------------------------------

    def _value(self, start: int, end: int) -> Value:
        stripped = self.text[start:end].strip().rstrip(";").strip()
        literal = _literal_value(stripped)
        if literal is not None:
            return literal
        mask = list(self.mask[start:end])
        values: list[Value] = []
        self._sanitized_values(start, end, mask, values)
        normalized_receiver = self._normalized_values(start, end, mask, values)
        searchable = self._searchable(start, end, "".join(mask))
        self._source_values(start, end, mask, searchable, values)
        dynamic = False
        for name in self._variable_names(start, end, searchable):
            current = self._lookup(name)
            if current is None:
                dynamic = True
            else:
                values.append(current)
        merged = merge(*values) if values else Value()
        variable = merged.dynamic or dynamic or merged.tainted
        strings = [single or double for single, double in re.findall(r"""'([^']*)'|"([^"]*)\"""", stripped)]
        result = cast(
            Value,
            replace(
                merged,
                dynamic=variable,
                composed=variable and self._composed(stripped),
                prefix=_prefix(stripped),
                text=" ".join(strings)[:400],
            ),
        )
        return sanitize(result, {NORMALIZED}) if normalized_receiver else result

    def _call_close(self, joined: str, start: int, match_end: int) -> int:
        """Offset of the ')' closing a call whose '(' ends the match, or -1."""
        if joined[match_end - 1 : match_end] == "(":
            return matching_paren(self.mask, start + match_end - 1)
        return -1

    def _sanitized_values(self, start: int, end: int, mask: list[str], values: list[Value]) -> None:
        """Evaluate sanitizer calls, record them and blank them out of the mask."""
        joined = "".join(mask)
        for pattern, categories in self.catalog.sanitizers:
            for match in pattern.finditer(joined):
                close = self._call_close(joined, start, match.end())
                inner_end = close if 0 <= close < end else end
                inner = self._value(start + match.end(), inner_end)
                values.append(sanitize(cast(Value, replace(inner, composed=False)), categories))
                stop = (inner_end - start + 1) if close >= 0 else len(mask)
                for position in range(match.start(), min(stop, len(mask))):
                    mask[position] = " "
            joined = "".join(mask)

    def _normalized_values(self, start: int, end: int, mask: list[str], values: list[Value]) -> bool:
        """Evaluate path normalizers; return True when a receiver chain is normalized."""
        if self.catalog.normalizers is None:
            return False
        normalized_receiver = False
        joined = "".join(mask)
        for match in self.catalog.normalizers.finditer(joined):
            close = self._call_close(joined, start, match.end())
            if not 0 <= close < end:
                continue
            if joined[match.start()] == "." or joined[: match.start()].rstrip().endswith("."):
                # receiver.normalize(): the whole receiver chain is normalized
                # when the call ends the expression.
                normalized_receiver = normalized_receiver or not self.mask[close + 1 : end].strip().rstrip(";")
                continue
            inner = self._value(start + match.end(), close)
            values.append(sanitize(inner, {NORMALIZED}))
            for position in range(match.start(), close - start + 1):
                mask[position] = " "
        return normalized_receiver

    def _source_values(self, start: int, end: int, mask: list[str], searchable: str, values: list[Value]) -> None:
        subject = self.text[start:end] if self.catalog.variables == "dollar" else searchable
        for pattern, trust, description in self.catalog.sources:
            for match in pattern.finditer(subject):
                if any(mask[position] == " " and self.mask[start + position] != " " for position in range(match.start(), min(match.end(), len(mask)))):
                    continue  # inside a sanitizer call that was already evaluated
                step = FlowStep(
                    "SOURCE",
                    self._location(start + match.start(), start + match.end()),
                    _compact(self.text[start + match.start() : start + match.end()]),
                    f"Untrusted {description}.",
                )
                values.append(source_value(step, trust))


    def _searchable(self, start: int, end: int, mask: str) -> str:
        """The masked text with string-interpolation expressions restored."""
        if self.catalog.interpolation is None or self.catalog.variables != "bare":
            return mask
        restored = list(mask)
        text = self.text[start:end]
        for literal in re.finditer(r'"(?:\\.|[^"\\])*"|`[^`]*`', text):
            if self.language == "C#" and not text[: literal.start()].endswith(("$", "$@", "@$")):
                continue
            for inner in self.catalog.interpolation.finditer(literal.group(0)):
                for position in range(literal.start() + inner.start(1), literal.start() + inner.end(1)):
                    restored[position] = text[position]
        return "".join(restored)

    def _variable_names(self, start: int, end: int, mask: str) -> list[str]:
        kind = self.catalog.variables
        if kind == "dollar":
            names = self._dollar_names(start, end, mask)
        elif kind == "percent":
            names = [percent or bang for percent, bang in re.findall(r"%([A-Za-z_]\w*)%|!([A-Za-z_]\w*)!", self.text[start:end])]
        else:
            names = self._bare_names(mask)
        keywords = _KEYWORDS.get(self.language, set())
        return [name for name in dict.fromkeys(names) if name not in keywords]

    def _dollar_names(self, start: int, end: int, mask: str) -> list[str]:
        # Variables expand inside double quotes but not inside single quotes.
        searchable_chars = list(_mask_single_quoted(self.text[start:end]))
        for position, character in enumerate(mask):
            if character == " " and self.mask[start + position : start + position + 1] != " ":
                searchable_chars[position] = " "
        names = re.findall(r"\$\{?([A-Za-z_]\w*)", "".join(searchable_chars))
        return [name for name in names if not re.fullmatch(r"_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER|ENV)|args|env|Request|this", name)]

    @staticmethod
    def _bare_names(mask: str) -> list[str]:
        names: list[str] = []
        for match in re.finditer(r"(?<![\w.$:>@])(@{0,2}[A-Za-z_]\w*)", mask):
            following = mask[match.end() : match.end() + 3]
            if following.lstrip().startswith("(") or following.startswith("::"):
                continue  # function call or namespace
            names.append(match.group(1))
        return names


    def _composed(self, expression: str) -> bool:
        without = re.sub(r"""'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*\"""", "S", expression)
        if "S" in without and (self.catalog.concat in without.replace("S", "")):
            return True
        if self.catalog.interpolation is not None and self.catalog.interpolation.search(expression) and re.search(r"[\"`]", expression):
            return True
        return any(pattern.search(expression) for pattern in _FORMAT_CALLS)

    # Sinks ------------------------------------------------------------------------

    def _sinks(self, start: int, end: int) -> None:
        mask = self.mask[start:end]
        text = self.text[start:end]
        for sink in self.catalog.sinks:
            if sink.requires is not None and not sink.requires.search(text):
                continue
            for match in sink.pattern.finditer(mask):
                self._sink_match(sink, match, start, end)

    def _sink_match(self, sink: Sink, match: re.Match[str], start: int, end: int) -> None:
        call_start = start + match.start()
        spans = self._argument_spans(sink, start + match.end(), end)
        if not spans:
            return
        selected = self._program_arguments(sink, spans) if sink.multi_argument_safe else None
        if selected is None:
            selected = self._select(sink, spans)
        if not selected:
            return
        values = [self._value(a, b) for a, b in selected]
        value = merge(*values)
        category = rule(f"{self.catalog.prefix}-{sink.family}-001").category
        if category == HTTP_REQUEST and has_fixed_host(values[0].prefix):
            return
        direct = any(
            pattern.search(self.text[a:b]) for a, b in selected for pattern, _, _ in self.catalog.sources
        )
        certainty = sink.certainty if direct else weakest(sink.certainty, Confidence.MEDIUM)
        self._emit(sink, call_start, spans[-1][1], value, certainty)


    def _argument_spans(self, sink: Sink, after: int, end: int) -> list[tuple[int, int]]:
        if sink.argument in {REST, TOKEN}:
            rest_start = after
            rest_end = end
            if sink.argument == TOKEN:
                token = re.match(r"\s*(\"[^\"]*\"|'[^']*'|\S+)", self.text[rest_start:rest_end])
                if not token:
                    return []
                return [(rest_start + token.start(1), rest_start + token.end(1))]
            return [(rest_start, rest_end)] if self.text[rest_start:rest_end].strip() else []
        open_index = after - 1
        if self.mask[open_index : open_index + 1] != "(":
            # Ruby/PHP calls without parentheses: treat the rest of the statement as arguments.
            return split_arguments(self.mask, after, end)
        close = matching_paren(self.mask, open_index)
        if close < 0:
            close = end
        return split_arguments(self.mask, open_index + 1, close)

    def _select(self, sink: Sink, spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
        if sink.argument == ALL:
            return spans
        if sink.argument == AFTER_FIRST:
            return spans[1:]
        if sink.argument == LAST:
            return spans[-1:]
        index = {FIRST: 0, SECOND: 1, THIRD: 2}.get(sink.argument, 0)
        return [spans[index]] if index < len(spans) else []

    def _program_arguments(self, sink: Sink, spans: list[tuple[int, int]]) -> list[tuple[int, int]] | None:
        """Arguments that decide what runs for exec-style APIs without a shell.

        With a separate argument list only the program path matters (later
        arguments cannot start new commands). When the program is a shell or
        cmd.exe, the command text after it is interpreted, so every argument
        matters. Returns None for a single-argument call.
        """
        offset = 1 if sink.argument == SECOND else 0
        if len(spans) <= offset + 1:
            return None
        program = self.text[slice(*spans[offset])].strip().strip("\"'")
        if re.fullmatch(r"(?i)(?:/bin/|/usr/bin/)?(?:sh|bash|zsh|dash|ksh|cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh)", program):
            return spans[offset:]
        return spans[offset : offset + 1]

    def _emit(self, sink: Sink, call_start: int, call_end: int, value: Value, certainty: Confidence) -> None:
        rule_id = f"{self.catalog.prefix}-{sink.family}-001"
        definition = rule(rule_id)
        confidence = judge(definition.category, value, certainty=certainty)
        if confidence is None:
            return
        statement_end = min(len(self.text), max(call_end + 1, call_start + 1))
        location = self._location(call_start, statement_end)
        evidence = _compact(self.text[call_start:statement_end])[:300]
        sink_step = FlowStep("SINK", location, evidence, f"Value reaches {sink.label}.")
        flow = list(unique_steps((*value.flow, sink_step)))
        source = next((step.location for step in flow if step.kind == "SOURCE"), None)
        reason = definition.explanation
        if value.trust == LOCAL:
            reason += " The source is local input (command line or stdin)."
        elif value.trust == ENVIRONMENT:
            reason += " The source is an environment variable, which an attacker rarely controls."
        if confidence is not Confidence.HIGH and value.trust == REMOTE:
            reason += " The engine traced the value through variables without type or control-flow information."
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
                sink=sink.label,
                evidence=evidence,
                reason=reason,
                source=source,
                flow=flow,
                remediations=remediations_for(
                    rule_id,
                    evidence,
                    structured_suggestion(rule_id, self.language, evidence),
                ),
            )
        )

    def _location(self, start: int, end: int) -> Location:
        line, column = self.index.position(start)
        end_line, end_column = self.index.position(max(start, end))
        return Location(self.path, line, column, end_line, end_column, self._enclosing_name())


_KEYWORDS: dict[str, set[str]] = {
    "Java": {"new", "return", "null", "true", "false", "this", "super", "String", "int", "long", "var", "final", "instanceof", "class"},
    "C#": {"new", "return", "null", "true", "false", "this", "base", "string", "int", "var", "await", "is", "as", "typeof", "nameof"},
    "Go": {"nil", "true", "false", "return", "func", "make", "len", "string", "int", "byte", "go", "defer", "range"},
    "Ruby": {"nil", "true", "false", "self", "do", "end", "if", "unless", "then", "else", "and", "or", "not", "return", "params", "cookies", "request", "ENV", "ARGV"},
    "C": {"NULL", "sizeof", "return", "char", "int", "const", "void", "struct", "unsigned", "argv", "stdin"},
    "C++": {"NULL", "nullptr", "sizeof", "return", "char", "int", "const", "void", "auto", "std", "argv", "stdin", "new"},
}


def analyze_structured(relative_path: str, text: str, language: str) -> list[Finding]:
    catalog = CATALOGS.get(language)
    if catalog is None:
        return []
    return _Engine(relative_path, text, language, catalog).run()


def _prefix(expression: str) -> str | None:
    quoted = re.match(r"""(?:'((?:\\.|[^'\\])*)'|"((?:\\.|[^"\\$#{])*))""", expression)
    if not quoted:
        return None
    return quoted.group(1) if quoted.group(1) is not None else quoted.group(2)


def _compact(value: str) -> str:
    return " ".join(value.strip().split())[:500]


def _mask_single_quoted(text: str) -> str:
    """Blank single-quoted literals without treating apostrophes in double strings as delimiters."""
    result = list(text)
    quote: str | None = None
    escaped = False
    for index, character in enumerate(text):
        if escaped:
            escaped = False
        elif quote is not None and character == "\\":
            escaped = True
        elif quote is None and character in {"'", '"'}:
            quote = character
        elif character == quote:
            if quote == "'":
                result[index] = " "
            quote = None
            continue
        if quote == "'":
            result[index] = " "
    return "".join(result)


def _literal_value(stripped: str) -> Value | None:
    literal = re.fullmatch(r"""'((?:\\.|[^'\\])*)'|"((?:\\.|[^"\\$#{])*)\"""", stripped)
    if literal:
        return constant(next(group for group in literal.groups() if group is not None))
    if re.fullmatch(r"-?\d+(?:\.\d+)?", stripped):
        return constant(stripped)
    return None
