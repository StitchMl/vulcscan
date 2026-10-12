"""Version comparison per package ecosystem.

Used only to pick the fixed version that applies to the installed version from
an OSV advisory; OSV itself decides whether a version is affected. Every
function returns None when a version string cannot be parsed, and callers then
fall back to reporting without filtering.
"""

from __future__ import annotations

import re
from functools import cmp_to_key

_PEP440 = re.compile(
    r"^\s*v?(?:(?P<epoch>\d+)!)?(?P<release>\d+(?:\.\d+)*)"
    r"(?:[-_.]?(?P<pre_l>a|b|c|rc|alpha|beta|pre|preview)[-_.]?(?P<pre_n>\d+)?)?"
    r"(?:-(?P<post_n1>\d+)|[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>\d+)?)?"
    r"(?:[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>\d+)?)?"
    r"(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?\s*$",
    re.IGNORECASE,
)
_PRE_ORDER = {"a": 0, "alpha": 0, "b": 1, "beta": 1, "c": 2, "rc": 2, "pre": 2, "preview": 2}
_INFINITY = float("inf")


def compare(ecosystem: str, left: str, right: str) -> int | None:
    """Return -1, 0 or 1, or None when either version cannot be parsed."""
    key = _KEYS.get(ecosystem.casefold(), _semver_key)
    left_key, right_key = key(left), key(right)
    if left_key is None or right_key is None:
        return None
    padding = _PADDING.get(ecosystem.casefold())
    if padding is not None:
        return _compare_padded(left_key, right_key, padding)
    return (left_key > right_key) - (left_key < right_key)


def _compare_padded(left: tuple, right: tuple, padding) -> int:
    """Compare segment lists where a missing segment equals ``padding(other)``."""
    for index in range(max(len(left), len(right))):
        a = left[index] if index < len(left) else padding(right[index])
        b = right[index] if index < len(right) else padding(left[index])
        if a != b:
            return 1 if a > b else -1
    return 0


def sort_versions(ecosystem: str, versions: list[str]) -> list[str]:
    def order(left: str, right: str) -> int:
        result = compare(ecosystem, left, right)
        return result if result is not None else (left > right) - (left < right)

    return sorted(versions, key=cmp_to_key(order))


def _pep440_key(version: str):
    match = _PEP440.match(version)
    if not match:
        return None
    release = [int(part) for part in match.group("release").split(".")]
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    pre_label = match.group("pre_l")
    post = match.group("post_n1") or match.group("post_n2")
    has_post = match.group("post_n1") is not None or match.group("post_l") is not None
    dev = match.group("dev_l") is not None
    if pre_label:
        pre = (_PRE_ORDER[pre_label.lower()], int(match.group("pre_n") or 0))
    elif dev and not has_post:
        pre = (-_INFINITY, 0)
    else:
        pre = (_INFINITY, 0)
    return (
        int(match.group("epoch") or 0),
        tuple(release),
        pre,
        int(post or 0) if has_post else -_INFINITY,
        int(match.group("dev_n") or 0) if dev else _INFINITY,
    )


def _semver_key(version: str):
    """SemVer 2 ordering, tolerant of a 'v' prefix and more than three numbers."""
    text = version.strip()
    text = text[1:] if text[:1] in {"v", "V"} else text
    text = text.split("+", 1)[0]
    main, _, prerelease = text.partition("-")
    if not re.fullmatch(r"\d+(?:\.\d+)*", main):
        return None
    numbers = [int(part) for part in main.split(".")]
    numbers += [0] * (4 - len(numbers)) if len(numbers) < 4 else []
    if not prerelease:
        return (tuple(numbers), 1, ())
    identifiers = []
    for identifier in prerelease.split("."):
        if identifier.isdigit():
            identifiers.append((0, int(identifier), ""))
        else:
            identifiers.append((1, 0, identifier.casefold()))
    return (tuple(numbers), 0, tuple(identifiers))


def _rubygems_key(version: str):
    text = version.strip()
    if not re.fullmatch(r"[0-9]+(?:[.-]?[0-9A-Za-z]+)*", text):
        return None
    # Gem::Version: letter segments mark a prerelease and sort before numbers,
    # so 1.2.0.pre1 < 1.2.0 < 1.2.0.1.
    segments = re.findall(r"[0-9]+|[A-Za-z]+", text)
    return tuple((1, int(segment), "") if segment.isdigit() else (0, 0, segment.casefold()) for segment in segments)


_MAVEN_QUALIFIERS = {
    "alpha": 0,
    "a": 0,
    "beta": 1,
    "b": 1,
    "milestone": 2,
    "m": 2,
    "rc": 3,
    "cr": 3,
    "snapshot": 4,
    "": 5,
    "ga": 5,
    "final": 5,
    "release": 5,
    "sp": 6,
}


def _maven_key(version: str):
    text = version.strip().casefold()
    if not re.fullmatch(r"[0-9a-z]+(?:[.\-_][0-9a-z]+)*", text):
        return None
    tokens = re.findall(r"\d+|[a-z]+", text)
    key = []
    for token in tokens:
        if token.isdigit():
            key.append((1, int(token)))
        elif token in _MAVEN_QUALIFIERS:
            key.append((0, _MAVEN_QUALIFIERS[token]))
        else:
            key.append((0, 5.5))  # unknown qualifier sorts after release, before sp
    return tuple(key)


_PADDING = {
    "rubygems": lambda other: (1, 0, ""),
    # Maven pads with 0 next to a number and with the release qualifier next to a qualifier.
    "maven": lambda other: (1, 0) if other[0] == 1 else (0, 5),
}

_KEYS = {
    "pypi": _pep440_key,
    "npm": _semver_key,
    "crates.io": _semver_key,
    "cargo": _semver_key,
    "go": _semver_key,
    "nuget": _semver_key,
    "packagist": _semver_key,
    "composer": _semver_key,
    "rubygems": _rubygems_key,
    "maven": _maven_key,
}
