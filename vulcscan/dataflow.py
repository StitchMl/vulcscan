"""Abstract values shared by the data-flow engines."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field, replace

from .models import Confidence, FlowStep

# Trust level of the most dangerous source behind a value.
NO_SOURCE = 0
ENVIRONMENT = 1  # environment variables
LOCAL = 2  # command-line arguments, stdin, interactive input
REMOTE = 3  # network input: HTTP parameters, bodies, headers, cookies, uploads

SOURCE_CONFIDENCE = {
    REMOTE: Confidence.HIGH,
    LOCAL: Confidence.MEDIUM,
    ENVIRONMENT: Confidence.LOW,
}

# Sink categories. NORMALIZED is a marker, not a sink: the value went through
# realpath/resolve/normalize, which a later containment check needs.
COMMAND = "COMMAND_EXECUTION"
SQL = "SQL_EXECUTION"
CODE = "CODE_EXECUTION"
FILESYSTEM = "FILESYSTEM"
DESERIALIZATION = "DESERIALIZATION"
TEMPLATE = "TEMPLATE"
HTTP_REQUEST = "HTTP_REQUEST"
REDIRECT = "REDIRECT"
XML = "XML_PARSER"
NORMALIZED = "NORMALIZED_PATH"
ALL_SINKS = frozenset(
    {COMMAND, SQL, CODE, FILESYSTEM, DESERIALIZATION, TEMPLATE, HTTP_REQUEST, REDIRECT, XML}
)

# Path, request and redirect sinks only matter when a remote party controls the
# value. A CLI that opens the file named on its own command line is not a
# path-traversal vulnerability.
REMOTE_ONLY_CATEGORIES = frozenset({FILESYSTEM, HTTP_REQUEST, REDIRECT, TEMPLATE, XML})

SQL_KEYWORDS = re.compile(
    r"(?i)\b(?:select\s.+\sfrom|insert\s+into|update\s+\w+\s+set|delete\s+from|"
    r"replace\s+into|create\s+(?:table|index|view)|drop\s+(?:table|index|view)|"
    r"alter\s+table|truncate\s+table|union\s+select|where\s+\w+\s*(?:=|like|in\b))"
)

_NOT_CONSTANT = object()
NOT_CONSTANT = _NOT_CONSTANT  # sentinel: the value has no known literal


@dataclass(frozen=True, slots=True)
class Value:
    """What the engine knows about one expression.

    ``sources`` hold the SOURCE steps of untrusted data; ``params`` hold the
    indices of function parameters the value depends on (function summaries).
    ``sanitized`` lists sink categories for which a recognized sanitizer ran.
    """

    dynamic: bool = False
    sources: tuple[FlowStep, ...] = ()
    flow: tuple[FlowStep, ...] = ()
    params: frozenset[int] = frozenset()
    sanitized: frozenset[str] = frozenset()
    literal: object = _NOT_CONSTANT
    prefix: str | None = None
    composed: bool = False
    text: str = ""
    trust: int = NO_SOURCE
    origin: str | None = None
    derived_from: tuple[str, ...] = field(default=())

    @property
    def tainted(self) -> bool:
        return bool(self.sources or self.params)

    @property
    def constant(self) -> bool:
        return self.literal is not _NOT_CONSTANT

    def vulnerable_to(self, category: str) -> bool:
        return self.tainted and category not in self.sanitized


UNKNOWN = Value(dynamic=True)


def constant(value: object) -> Value:
    text = value if isinstance(value, str) else ""
    return Value(literal=value, prefix=text if isinstance(value, str) else None, text=text[:200])


def source_value(step: FlowStep, trust: int) -> Value:
    return Value(dynamic=True, sources=(step,), flow=(step,), trust=trust)


def sanitize(value: Value, categories: Iterable[str]) -> Value:
    categories = frozenset(categories)
    if categories >= ALL_SINKS:
        # Safe for every sink (a number, an allowlisted literal): drop the taint
        # so the source no longer appears in later flows.
        return Value(dynamic=value.dynamic or value.tainted, sanitized=value.sanitized | categories)
    return replace(value, sanitized=value.sanitized | categories)


def with_step(value: Value, step: FlowStep) -> Value:
    if not value.tainted:
        return value
    return replace(value, flow=unique_steps((*value.flow, step)))


def merge(*values: Value) -> Value:
    """Join values that flow into one expression or one program point."""
    present = [item for item in values if item is not None]
    if not present:
        return Value()
    if len(present) == 1:
        return present[0]
    tainted = [item for item in present if item.tainted]
    # Constants carry no sanitizer information; only non-constant parts vote.
    variable = [item for item in present if item.tainted or item.dynamic]
    sanitized: frozenset[str] = frozenset()
    if variable:
        sanitized = variable[0].sanitized
        for item in variable[1:]:
            sanitized &= item.sanitized
    first = present[0]
    literal = first.literal
    if any(item.literal is not literal and item.literal != literal for item in present[1:]):
        literal = _NOT_CONSTANT
    prefix = first.prefix
    if any(item.prefix != prefix for item in present[1:]):
        prefix = None
    origin = first.origin
    if any(item.origin != origin for item in present[1:]):
        origin = None
    return Value(
        dynamic=any(item.dynamic for item in present),
        sources=unique_steps(step for item in present for step in item.sources),
        flow=unique_steps(step for item in present for step in item.flow),
        params=frozenset(index for item in present for index in item.params),
        sanitized=sanitized,
        literal=literal,
        prefix=prefix,
        composed=any(item.composed for item in present),
        text=" ".join(item.text for item in present if item.text)[:400],
        trust=max((item.trust for item in tainted), default=NO_SOURCE),
        origin=origin,
        derived_from=tuple(dict.fromkeys(name for item in present for name in item.derived_from)),
    )


def concatenate(parts: list[Value]) -> Value:
    """Value of string concatenation or interpolation of ``parts`` in order."""
    if not parts:
        return constant("")
    joined = merge(*parts)
    prefix = ""
    for part in parts:
        if part.constant and isinstance(part.literal, str):
            prefix += part.literal
            continue
        if part.prefix:
            prefix += part.prefix
        break
    literal: object = _NOT_CONSTANT
    if all(part.constant and isinstance(part.literal, str) for part in parts):
        literal = "".join(str(part.literal) for part in parts)
    return replace(
        joined,
        literal=literal,
        prefix=prefix or None,
        composed=joined.dynamic or joined.tainted or joined.composed,
        origin=None,
    )


def unique_steps(steps: Iterable[FlowStep]) -> tuple[FlowStep, ...]:
    result: list[FlowStep] = []
    seen: set[tuple[str, str, int, int | None, str]] = set()
    for step in steps:
        key = (step.kind, step.location.file, step.location.line, step.location.column, step.code)
        if key not in seen:
            seen.add(key)
            result.append(step)
    return tuple(result)


def has_fixed_host(prefix: str | None) -> bool:
    """True when a URL prefix already fixes scheme and host."""
    return bool(prefix and re.match(r"(?i)^[a-z][a-z0-9+.-]*://[^/?#@\\\s]+[/?#]", prefix))


def is_local_path(prefix: str | None) -> bool:
    """True when a redirect target prefix keeps the browser on the same origin."""
    return bool(prefix and re.match(r"^/[^/\\]", prefix))


def weakest(*levels: Confidence) -> Confidence:
    order = {Confidence.HIGH: 0, Confidence.MEDIUM: 1, Confidence.LOW: 2}
    return max(levels, key=order.__getitem__)


def judge(
    category: str,
    value: Value,
    *,
    certainty: Confidence = Confidence.HIGH,
    unknown_origin: bool = False,
    sql_evidence: bool = True,
) -> Confidence | None:
    """Decide whether ``value`` reaching a ``category`` sink is a finding.

    Returns the finding confidence or None. ``certainty`` caps the confidence
    when the sink itself is uncertain. ``unknown_origin`` enables findings for
    values of unknown origin (command, code and SQL sinks only).
    """
    if category in value.sanitized:
        return None
    if value.sources:
        if category in REMOTE_ONLY_CATEGORIES and value.trust < REMOTE:
            return None
        return weakest(SOURCE_CONFIDENCE[value.trust], certainty)
    if not unknown_origin or not value.dynamic:
        return None
    if category == SQL:
        return weakest(Confidence.MEDIUM, certainty) if value.composed and sql_evidence else None
    if category in {COMMAND, CODE}:
        return weakest(Confidence.MEDIUM if value.composed else Confidence.LOW, certainty)
    return None
