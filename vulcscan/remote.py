"""Conservative identification of findings backed by explicit remote sources."""
from __future__ import annotations

import re

from .models import Finding

_HTTP = re.compile(
    r"\b(?:HTTP|network|remote|request|req\.|headers?|cookies?|query parameter|"
    r"websocket|socket\.recv|\$_(?:GET|POST|REQUEST|COOKIE|FILES))\b",
    re.IGNORECASE,
)


def has_remote_source(finding: Finding) -> bool:
    """Only classify explicit SOURCE steps; do not infer remoteness from severity."""
    return any(
        step.kind.upper() == "SOURCE"
        and bool(_HTTP.search(step.description + " " + step.code))
        for step in finding.flow
    )
