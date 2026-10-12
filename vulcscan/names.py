"""Identifier and literal heuristics for credential and randomness rules."""

from __future__ import annotations

import re

_COMPONENT = re.compile(r"[A-Z]+(?=[A-Z][a-z]|\d|\b|_)|[A-Z]?[a-z]+|\d+")

_CREDENTIAL_LAST = {"password", "passwd", "pwd", "passphrase", "secret", "token", "apikey", "credentials", "credential"}
_KEY_QUALIFIERS = {"api", "secret", "private", "access", "auth", "signing", "encryption", "master", "client", "app"}
_RANDOM_WORDS = {"token", "secret", "password", "passwd", "nonce", "salt", "otp", "csrf", "apikey"}
_RANDOM_LAST = {"key", "code", "pin", "sid"}
_RANDOM_QUALIFIERS = {"api", "secret", "session", "reset", "verification", "verify", "auth", "activation", "confirm", "confirmation", "signing", "otp", "invite", "recovery", "access"}

_PLACEHOLDER = re.compile(
    r"(?i)^(?:change[_-]?me|example|sample|placeholder|dummy|fake|test(?:ing)?|none|null|nil|todo|tbd|"
    r"redacted|secret|password|passwd|xxx+|\*+|\.+|your[_-].*|my[_-]?(?:password|secret|token).*|"
    r".*(?:example|placeholder|changeme|change_me|dummy|sample).*)$"
)
_TEMPLATE = re.compile(r"\$\{|\{\{|%\(|^\$[A-Za-z_]|^%[A-Za-z_]+%$|^<.*>$|\{[A-Za-z_]*\}")
_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")


def components(identifier: str) -> list[str]:
    """Split ``apiKey``/``API_KEY``/``api-key`` into lowercase words."""
    words: list[str] = []
    for chunk in re.split(r"[^A-Za-z0-9]+", identifier):
        words.extend(match.group(0).lower() for match in _COMPONENT.finditer(chunk))
    return words


def is_credential_name(identifier: str) -> bool:
    words = components(identifier)
    if not words:
        return False
    last = words[-1]
    if last in _CREDENTIAL_LAST:
        return True
    if last == "key" and len(words) >= 2 and words[-2] in _KEY_QUALIFIERS:
        return True
    return len(words) >= 2 and words[-2] == "client" and last == "secret"


def is_random_sensitive_name(identifier: str) -> bool:
    words = components(identifier)
    if any(word in _RANDOM_WORDS for word in words):
        return True
    if words and words[-1] in _RANDOM_LAST and any(word in _RANDOM_QUALIFIERS for word in words[:-1]):
        return True
    return identifier.casefold() in {"sid", "session_id", "sessionid", "session_key"}


def mentions_password(text: str) -> bool:
    return any(word in {"password", "passwd", "pwd", "passphrase"} for word in components(text))


def looks_like_secret(value: str, identifier: str = "") -> bool:
    """Reject empty, placeholder, templated and descriptive literals."""
    candidate = value.strip()
    if len(candidate) < 8 or len(candidate) > 512:
        return False
    if any(char.isspace() for char in candidate):
        return False
    if _PLACEHOLDER.match(candidate) or _TEMPLATE.search(candidate):
        return False
    if _ENV_NAME.match(candidate) and "_" in candidate:
        return False  # names an environment variable
    if candidate.casefold() == identifier.casefold():
        return False
    if len(set(candidate)) <= 2:
        return False
    if candidate.startswith(("/", "./", "../", "~/")) or re.match(r"^[A-Za-z]:\\", candidate):
        return False
    if re.match(r"(?i)^[a-z][a-z0-9+.-]*://", candidate) and "@" not in candidate:
        return False
    return True
