"""Line and configuration rules for non-Python files.

These rules look for explicit unsafe settings and literals: a disabled
certificate check, a hardcoded credential, a weak cipher name. Python files use
the AST equivalents in :mod:`vulcscan.python_analysis`; only the private-key
and known-token checks run on them here.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from .models import Confidence, Finding, Location
from .names import is_credential_name, is_random_sensitive_name, looks_like_secret, mentions_password
from .rules import RULES, remediations_for
from .source import blank_comments, comment_style, split_lines

MAX_LINE_LENGTH = 4000  # longer lines are minified or generated; regexes skip them

_PRIVATE_KEY = re.compile(r"-----BEGIN ((?:RSA |DSA |EC |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?)-----")
_KEY_MATERIAL = re.compile(r"[A-Za-z0-9+/]{40,}")
_KNOWN_TOKENS = (
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "GitHub token"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b"), "GitHub fine-grained token"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "Slack token"),
    (re.compile(r"\bsk_live_[A-Za-z0-9]{20,}\b"), "Stripe live secret key"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "Google API key"),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "AWS access key ID"),
    (re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"), "GitLab token"),
)
_KEY_VALUE = re.compile(
    r"""(?P<key>[A-Za-z_][\w.-]*)["']?\s*(?::=|=>|:|=)\s*(?:[rubfRUBF@$]*)(?P<quote>["'`])(?P<value>[^"'`\n]{8,})(?P=quote)"""
)
_CONFIG_VALUE = re.compile(r"""^\s*(?:export\s+|ENV\s+)?(?P<key>[A-Za-z_][\w.-]*)\s*[:=]?\s*(?:=|:|\s)\s*(?P<value>[^\s#;'"]{8,})\s*$""")
_CONFIG_LANGUAGES = {"Environment", "YAML", "Configuration", "TOML", "Dockerfile", "HCL", "Terraform"}
_EXAMPLE_FILE = re.compile(r"(?i)(?:example|sample|template|\.dist$|\.tpl$|\.tmpl$)")

_TLS_PATTERNS = (
    re.compile(r"\brejectUnauthorized\s*['\"]?\s*:\s*false\b"),
    re.compile(r"\bNODE_TLS_REJECT_UNAUTHORIZED\b\s*(?:=|:)\s*['\"]?0\b"),
    re.compile(r"\bInsecureSkipVerify\s*:\s*true\b"),
    re.compile(r"ServerCertificateCustomValidationCallback\s*=\s*(?:[^;]*=>\s*true|HttpClientHandler\s*\.\s*DangerousAcceptAnyServerCertificateValidator)"),
    re.compile(r"ServerCertificateValidationCallback\s*\+?=\s*[^;]*=>\s*true"),
    re.compile(r"CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0)\b|CURLOPT_SSL_VERIFYHOST\s*,\s*0\b"),
    re.compile(r"""['"]verify['"]\s*=>\s*false\b"""),
    re.compile(r"\b(?:NoopHostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER|AllowAllHostnameVerifier)\b"),
    re.compile(r"\bVERIFY_NONE\b"),
    re.compile(r"\bcurl\b[^\n|;]*\s(?:-k|--insecure)\b"),
    re.compile(r"\bwget\b[^\n|;]*\s--no-check-certificate\b"),
    re.compile(r"-SkipCertificateCheck\b"),
    re.compile(r"\bvalidate_certs\s*:\s*(?:false|no)\b"),
    re.compile(r"(?i)\bsslVerify\s*=\s*false\b"),
)
_TLS_LANGUAGES = {"JavaScript", "TypeScript", "Go", "C#", "PHP", "Java", "Ruby", "Shell", "PowerShell", "YAML", "Configuration", "Dockerfile", "Kotlin"}

_WEAK_CIPHER = (
    re.compile(r"""Cipher\s*\.\s*getInstance\s*\(\s*"(?:DES|DESede|TripleDES|RC2|RC4|ARCFOUR|Blowfish)(?:/[^"]*)?"|Cipher\s*\.\s*getInstance\s*\(\s*"AES(?:/ECB/[^"]*)?"\s*\)"""),
    re.compile(r"\b(?:DES|TripleDES|RC2)\s*\.\s*Create\s*\(|new\s+(?:DES|TripleDES|RC2)CryptoServiceProvider\b|\bCipherMode\s*\.\s*ECB\b"),
    re.compile(r"""createCipher(?:iv)?\s*\(\s*['"`](?:des|des-ede3?(?:-cbc)?|des-cbc|rc2|rc4|bf|blowfish|aes-\d+-ecb)\b""", re.IGNORECASE),
    re.compile(r"\b(?:des\s*\.\s*NewCipher|des\s*\.\s*NewTripleDESCipher|rc4\s*\.\s*NewCipher)\s*\("),
    re.compile(r"""openssl_(?:en|de)crypt\s*\([^,]*,\s*['"](?:des|bf|rc2|rc4|aes-\d+-ecb)""", re.IGNORECASE),
    re.compile(r"\bMCRYPT_(?:DES|3DES|BLOWFISH|RC2)\b|\bMCRYPT_MODE_ECB\b"),
    re.compile(r"""OpenSSL::Cipher\s*\.\s*new\s*\(\s*['"](?:des|bf|rc4|rc2|aes-\d+-ecb)""", re.IGNORECASE),
)
_WEAK_HASH_DIRECT = (
    re.compile(r"""createHash\s*\(\s*['"`](?:md5|sha1|sha256|sha512)['"`]\s*\)\s*\.\s*update\s*\(([^)]*)\)""", re.IGNORECASE),
    re.compile(r"(?<![\w>$])(?:md5|sha1)\s*\(([^)]*)\)"),
    re.compile(r"""(?<![\w>$])hash\s*\(\s*['"](?:md5|sha1|sha256|sha512)['"]\s*,([^)]*)\)""", re.IGNORECASE),
    re.compile(r"\b(?:MD5|SHA1|SHA256|SHA512)\s*\.\s*(?:HashData|Create\s*\(\s*\)\s*\.\s*ComputeHash)\s*\(([^;]*)\)"),
    re.compile(r"\b(?:md5|sha1|sha256|sha512)\s*\.\s*Sum(?:256|512)?\s*\(([^)]*)\)"),
    re.compile(r"Digest::(?:MD5|SHA1|SHA256|SHA512)\s*\.\s*(?:hexdigest|digest|base64digest)\s*\(([^)]*)\)"),
)
_JAVA_DIGEST = re.compile(r"""\b(\w+)\s*=\s*MessageDigest\s*\.\s*getInstance\s*\(\s*"(?:MD5|SHA-?1|SHA-?256|SHA-?512)"\s*\)""")
_WEAK_RANDOM = re.compile(r"\bMath\s*\.\s*random\s*\(|\bnew\s+Random\s*\(|(?<![\w>$:])(?:rand|mt_rand|uniqid|lcg_value)\s*\(|\bRandom\s*\.\s*new\b|\brand\s*\.\s*(?:Intn|Int63|Int31|Int|Read)\s*\(")
_ASSIGNED_NAME = re.compile(r"(?:\$|@{1,2})?([A-Za-z_]\w*)\s*(?::\s*[\w<>\[\]]+\s*)?(?::=|=)(?!=)")

_DEBUG = (
    re.compile(r"^\s*APP_DEBUG\s*=\s*(?:true|1)\s*$", re.IGNORECASE),
    re.compile(r"^\s*(?:DJANGO_)?DEBUG\s*=\s*(?:True|true|1|on)\s*$"),
    re.compile(r"""<compilation\b[^>]*\bdebug\s*=\s*["']true["']""", re.IGNORECASE),
    re.compile(r"^\s*display_errors\s*=\s*(?:On|1|true)\s*$", re.IGNORECASE),
    re.compile(r"""ini_set\s*\(\s*['"]display_errors['"]\s*,\s*['"]?(?:1|On|true)""", re.IGNORECASE),
)

_XXE_EXPLICIT = (
    re.compile(r"\bXmlResolver\s*=\s*new\s+XmlUrlResolver\b"),
    re.compile(r"\bDtdProcessing\s*=\s*DtdProcessing\s*\.\s*Parse\b"),
    re.compile(r"\bLIBXML_NOENT\b"),
    re.compile(r"\blibxml_disable_entity_loader\s*\(\s*false\s*\)"),
    re.compile(r"\bnoent\s*:\s*true\b"),
    re.compile(r"\bParseOptions::NOENT\b|\.\s*noent\b"),
    re.compile(r"""setFeature\s*\(\s*"http://(?:xml\.org/sax/features/external-(?:general|parameter)-entities|apache\.org/xml/features/nonvalidating/load-external-dtd)"\s*,\s*true\s*\)"""),
)
_JAVA_XML_FACTORY = re.compile(r"\b(DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory|SchemaFactory)\s*\.\s*newInstance\s*\(")
_JAVA_XML_HARDENING = re.compile(
    r"disallow-doctype-decl|ACCESS_EXTERNAL_DTD|ACCESS_EXTERNAL_STYLESHEET|IS_SUPPORTING_EXTERNAL_ENTITIES|SUPPORT_DTD|external-general-entities\"\s*,\s*false|setExpandEntityReferences\s*\(\s*false"
)

_CORS_REFLECT = (
    re.compile(r"\bcors\s*\(\s*\{[^}]*\borigin\s*:\s*(?:true|\(?[\w\s,]*\)?\s*=>\s*true)[^}]*\}", re.DOTALL),
    re.compile(r"""Access-Control-Allow-Origin['"]?\s*,\s*(?:req|request)\s*\.\s*(?:headers\s*\.\s*origin|header\s*\(\s*['"]origin)""", re.IGNORECASE),
    re.compile(r"""header\s*\(\s*['"]Access-Control-Allow-Origin:\s*['"]\s*\.\s*\$_SERVER\s*\[\s*['"]HTTP_ORIGIN""", re.IGNORECASE),
    re.compile(r"\bSetIsOriginAllowed\s*\(\s*\(?\s*\w*\s*\)?\s*=>\s*true\s*\)"),
    re.compile(r"""\ballowedOriginPatterns\s*\(\s*"\*"\s*\)|\bAllowOriginFunc\s*:\s*func\s*\([^)]*\)\s*bool\s*\{\s*return\s+true"""),
)
_CORS_CREDENTIALS = re.compile(r"""\bcredentials\s*:\s*true\b|Access-Control-Allow-Credentials['"]?\s*[,:]\s*['"]?true|\bAllowCredentials\s*(?:\(\s*\)|:\s*true)|\ballowCredentials\s*\(\s*true\s*\)""", re.IGNORECASE)

_PRIVILEGED = re.compile(r"""\bprivileged["']?\s*:\s*true\b""")


def lexical_findings(file_name: str, relative_path: str, language: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    raw_lines = split_lines(text)

    def add(rule_id: str, line: int, column: int, sink: str, evidence: str, confidence: Confidence | None = None) -> None:
        definition = RULES[rule_id]
        evidence = evidence.strip()[:300]
        findings.append(
            Finding(
                rule_id=rule_id,
                name=definition.name,
                cwe=definition.cwe,
                severity=definition.severity,
                confidence=confidence or definition.default_confidence,
                category=definition.category,
                language=language,
                location=Location(relative_path, line, max(column, 1), line),
                sink=sink,
                evidence=evidence,
                reason=definition.explanation,
                remediations=remediations_for(rule_id, evidence),
            )
        )

    _private_keys(raw_lines, add)
    if language == "SVG":
        for number, line in enumerate(raw_lines, 1):
            match = re.search(r"(?i)<\s*script\b|\bon[a-z]+\s*=|(?:href|xlink:href)\s*=\s*['\"]\s*javascript:|<\s*foreignObject\b", line)
            if match:
                add("SVG-ACTIVE-001", number, match.start() + 1, "active SVG content", line)
    example = bool(_EXAMPLE_FILE.search(file_name))
    for number, line in enumerate(raw_lines, 1):
        if len(line) > MAX_LINE_LENGTH:
            continue
        for pattern, label in _KNOWN_TOKENS:
            match = pattern.search(line)
            if match and not example:
                add("SECRET-001", number, match.start() + 1, label, _redact(line, match.group(0)), Confidence.HIGH)
    if language == "Python":
        return findings

    code_lines = split_lines(blank_comments(text, comment_style(language)))
    for number, line in enumerate(code_lines, 1):
        if len(line) > MAX_LINE_LENGTH or not line.strip():
            continue
        if not example:
            _secret(line, number, language, add)
        if language == "Shell":
            password = re.search(r"(?i)\b(?:mysql|mysqldump)\b[^\n]*\s-p(?:assword)?(?:=)?\s*['\"]?([^\s'\"]{4,})", line)
            if password:
                add("SECRET-001", number, password.start(1) + 1, "database CLI password", _redact(line, password.group(1)), Confidence.HIGH)
        if language == "Configuration":
            remote_include = re.search(r"(?i)^\s*allow_url_include\s*=\s*(?:on|1|true)\s*$", line)
            if remote_include:
                add("PHP-URL-INCLUDE-001", number, remote_include.start() + 1, "allow_url_include", line)
        if language in _TLS_LANGUAGES:
            for pattern in _TLS_PATTERNS:
                match = pattern.search(line)
                if match:
                    add("TLS-VERIFY-001", number, match.start() + 1, "TLS verification option", line)
                    break
        for pattern in _WEAK_CIPHER:
            match = pattern.search(line)
            if match:
                add("WEAK-CIPHER-001", number, match.start() + 1, match.group(0)[:60], line)
                break
        for pattern in _WEAK_HASH_DIRECT:
            match = pattern.search(line)
            if match and mentions_password(match.group(1)):
                add("WEAK-HASH-001", number, match.start() + 1, match.group(0).split("(", 1)[0], line)
                break
        if language == "SQL" and re.search(r"(?i)\bMD5\s*\(", line) and re.search(r"(?i)password|passwd|pwd", text):
            match = re.search(r"(?i)\bMD5\s*\(", line)
            assert match is not None
            add("WEAK-HASH-001", number, match.start() + 1, "SQL MD5 password hash", line)
        random_match = _WEAK_RANDOM.search(line)
        if random_match and language not in _CONFIG_LANGUAGES:
            assigned = _ASSIGNED_NAME.search(line[: random_match.start()])
            go_crypto = language == "Go" and '"crypto/rand"' in text and '"math/rand"' not in text
            if assigned and is_random_sensitive_name(assigned.group(1)) and not go_crypto:
                add("WEAK-RANDOM-001", number, random_match.start() + 1, "non-cryptographic PRNG", line)
        if not example:
            for pattern in _DEBUG:
                match = pattern.search(line)
                if match:
                    add("DEBUG-001", number, match.start() + 1, "debug configuration", line)
                    break
        for pattern in _XXE_EXPLICIT:
            match = pattern.search(line)
            if match:
                add("XXE-001", number, match.start() + 1, "XML parser configuration", line)
                break
        if language in {"YAML", "JSON"}:
            match = _PRIVILEGED.search(line)
            if match:
                add("K8S-PRIV-001", number, match.start() + 1, "privileged: true", line)
    _java_digest(code_lines, add)
    _java_xml_factories(language, text, code_lines, add)
    _cors(text if language not in _CONFIG_LANGUAGES else "", code_lines, add)
    if language == "Dockerfile":
        _dockerfile(code_lines, add)
    if language == "PHP":
        _php_xss(text, add)
        _database_race(text, add)
        _php_request_security(text, add)
    if language == "SQL":
        _sql_cleartext_password(text, add)
    return findings


def _php_xss(text: str, add: Callable[..., None]) -> None:
    statements = re.compile(r"(?is)\becho\b(?P<body>.*?);")
    sanitizer = re.compile(
        r"(?is)\b(?:htmlspecialchars|htmlentities|strip_tags|json_encode)\s*"
        r"\((?:[^()]|\([^()]*\))*\)"
    )
    numeric_cast = re.compile(
        r"(?is)\((?:int|integer|float|double|bool|boolean)\)\s*"
        r"\$[A-Za-z_]\w*\s*\[\s*['\"][^'\"]+['\"]\s*\]"
    )
    tainted_names: set[str] = set()
    for assignment in re.finditer(
        r"(?is)\$(?P<name>[A-Za-z_]\w*)\s*=\s*(?P<rhs>[^;]{0,500}\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\b[^;]*);",
        text,
    ):
        rhs = assignment.group("rhs")
        if re.search(r"(?i)(?:\((?:int|integer|float|double|bool|boolean)\)\s*\$_|\b(?:intval|floatval|boolval)\s*\()", rhs):
            continue
        tainted_names.add(assignment.group("name"))
    scalar = "|".join(re.escape(name) for name in sorted(tainted_names))
    dynamic_pattern = r"\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\b|\$[A-Za-z_]\w*\s*\[\s*['\"][^'\"]+['\"]\s*\]"
    if scalar:
        dynamic_pattern += rf"|\$(?:{scalar})\b"
    dynamic = re.compile(dynamic_pattern)
    for statement in statements.finditer(text):
        body = numeric_cast.sub("", sanitizer.sub("", statement.group("body")))
        match = dynamic.search(body)
        if not match:
            continue
        absolute = statement.start("body") + match.start()
        line = text.count("\n", 0, absolute) + 1
        column = absolute - text.rfind("\n", 0, absolute)
        evidence = text[statement.start():statement.end()].replace("\n", " ")[:300]
        add("PHP-XSS-001", line, column, "PHP echo", evidence)


def _database_race(text: str, add: Callable[..., None]) -> None:
    if re.search(r"(?i)\b(?:begin(?:_transaction)?|start\s+transaction|for\s+update)\b", text):
        return
    select = re.search(r"(?is)\bSELECT\b[^;]{0,600}\b(?P<field>[A-Za-z_]\w*(?:remaining|rimanenti|stock|balance|credit|uses)[A-Za-z_]*)\b[^;]*;", text)
    if not select:
        return
    field = select.group("field")
    tail = text[select.end():]
    update = re.search(
        rf"(?is)\bUPDATE\b[^;]{{0,1200}}\b{re.escape(field)}\b\s*=\s*\b{re.escape(field)}\b\s*-\s*1\b[^;]*;",
        tail,
    )
    check = re.search(rf"(?is)\bif\s*\([^)]*\b{re.escape(field)}\b[^)]*>\s*0", tail)
    if not update or not check or check.start() > update.start():
        return
    absolute = select.end() + update.start()
    line = text.count("\n", 0, absolute) + 1
    column = absolute - text.rfind("\n", 0, absolute)
    evidence = update.group(0).replace("\n", " ")[:300]
    add("DB-RACE-001", line, column, "database UPDATE", evidence)


def _php_request_security(text: str, add: Callable[..., None]) -> None:
    upload = re.search(r"(?is)move_uploaded_file\s*\(", text)
    client_mime = re.search(r"(?is)\$_FILES\s*\[[^\]]+\]\s*\[\s*['\"]type['\"]\s*\]", text)
    content_check = re.search(r"(?i)\b(?:finfo_file|mime_content_type|getimagesize|exif_imagetype)\s*\(", text)
    if upload and client_mime and not content_check:
        line = text.count("\n", 0, upload.start()) + 1
        column = upload.start() - text.rfind("\n", 0, upload.start())
        evidence = text[upload.start() : text.find(";", upload.start()) + 1].replace("\n", " ")[:300]
        add("UPLOAD-MIME-001", line, column, "move_uploaded_file", evidence)

    state_change = re.search(
        r"(?is)move_uploaded_file\s*\(|(?:INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)[^;]{0,800}",
        text,
    )
    post_handler = re.search(r"(?is)\$_SERVER\s*\[\s*['\"]REQUEST_METHOD['\"]\s*\].{0,80}POST|\$_POST\b", text)
    csrf_check = re.search(r"(?i)\b(?:csrf|xsrf|anti_forgery|request_token)\b|hash_equals\s*\(", text)
    if state_change and post_handler and not csrf_check:
        line = text.count("\n", 0, state_change.start()) + 1
        column = state_change.start() - text.rfind("\n", 0, state_change.start())
        evidence = text[state_change.start() : state_change.start() + 180].replace("\n", " ")
        add("CSRF-001", line, column, "state-changing POST handler", evidence)

    authenticated = re.search(r"(?is)\$_SESSION\s*\[[^\]]+\]\s*=", text)
    credential_check = re.search(r"(?i)password|passwd|credential|login", text)
    if authenticated and credential_check and not re.search(r"(?i)\bsession_regenerate_id\s*\(", text):
        line = text.count("\n", 0, authenticated.start()) + 1
        column = authenticated.start() - text.rfind("\n", 0, authenticated.start())
        evidence = text[authenticated.start() : text.find(";", authenticated.start()) + 1].replace("\n", " ")[:300]
        add("SESSION-FIXATION-001", line, column, "authenticated session assignment", evidence)


def _sql_cleartext_password(text: str, add: Callable[..., None]) -> None:
    pattern = re.compile(
        r"(?is)\bINSERT\s+INTO\s+([A-Za-z_]\w*)\s*\((?P<columns>[^)]*\b(?:password|passwd|pwd)\b[^)]*)\)\s*VALUES\s*(?P<values>[^;]+);"
    )
    for match in pattern.finditer(text):
        values = match.group("values")
        if re.search(r"(?i)\b(?:MD5|SHA1|SHA2|CRYPT|PASSWORD_HASH|BCRYPT|ARGON2)\s*\(", values):
            continue
        if not re.search(r"['\"][^'\"]{4,}['\"]", values):
            continue
        line = text.count("\n", 0, match.start()) + 1
        column = match.start() - text.rfind("\n", 0, match.start())
        evidence = re.sub(r"(['\"])[^'\"]{4,}\1", r"\1<redacted>\1", match.group(0).replace("\n", " "))[:300]
        add("CLEARTEXT-PASSWORD-001", line, column, "SQL seed password", evidence)


def _private_keys(lines: list[str], add: Callable[..., None]) -> None:
    for number, line in enumerate(lines, 1):
        match = _PRIVATE_KEY.search(line)
        if not match:
            continue
        following = line[match.end() :] + " " + (lines[number] if number < len(lines) else "")
        if _KEY_MATERIAL.search(following.replace("\\n", " ")):
            add("PRIVATE-KEY-001", number, match.start() + 1, match.group(1), f"-----BEGIN {match.group(1)}----- <key material redacted>")


def _secret(line: str, number: int, language: str, add: Callable[..., None]) -> None:
    for match in _KEY_VALUE.finditer(line):
        key = match.group("key").rsplit(".", 1)[-1]
        if is_credential_name(key) and looks_like_secret(match.group("value"), key):
            add("SECRET-001", number, match.start("key") + 1, key, _redact(line, match.group("value")))
            return
    if language in _CONFIG_LANGUAGES:
        match = _CONFIG_VALUE.match(line)
        if match:
            key = match.group("key").rsplit(".", 1)[-1]
            value = match.group("value")
            if is_credential_name(key) and looks_like_secret(value, key) and not value.startswith(("$", "%", "{")):
                add("SECRET-001", number, match.start("key") + 1, key, _redact(line, value))


def _java_digest(lines: list[str], add: Callable[..., None]) -> None:
    digests: set[str] = set()
    for number, line in enumerate(lines, 1):
        assignment = _JAVA_DIGEST.search(line)
        if assignment:
            digests.add(assignment.group(1))
        for name in digests:
            usage = re.search(rf"\b{re.escape(name)}\s*\.\s*(?:digest|update)\s*\(([^;]*)\)", line)
            if usage and mentions_password(usage.group(1)):
                add("WEAK-HASH-001", number, usage.start() + 1, "MessageDigest", line)
                break


def _java_xml_factories(language: str, text: str, lines: list[str], add: Callable[..., None]) -> None:
    if language not in {"Java", "Kotlin"} or _JAVA_XML_HARDENING.search(text):
        return
    for number, line in enumerate(lines, 1):
        match = _JAVA_XML_FACTORY.search(line)
        if match:
            # The file creates the factory without any hardening call in this
            # file. The hardening may live elsewhere, so confidence stays MEDIUM.
            add("XXE-001", number, match.start() + 1, match.group(1), line, Confidence.MEDIUM)


def _cors(text: str, lines: list[str], add: Callable[..., None]) -> None:
    if not text:
        return
    code = "\n".join(lines)
    for pattern in _CORS_REFLECT:
        for match in pattern.finditer(code):
            window_start = code.rfind("\n", 0, max(0, match.start() - 1500)) + 1
            window = code[window_start : match.end() + 1500]
            if _CORS_CREDENTIALS.search(match.group(0)) or _CORS_CREDENTIALS.search(window):
                line = code.count("\n", 0, match.start()) + 1
                column = match.start() - (code.rfind("\n", 0, match.start()) + 1) + 1
                add("CORS-001", line, column, "origin reflection with credentials", lines[line - 1])
                return


def _dockerfile(lines: list[str], add: Callable[..., None]) -> None:
    final_from = None
    for number, line in enumerate(lines, 1):
        if re.match(r"(?i)\s*FROM\s+", line):
            final_from = number
    if final_from is None:
        return
    stage = lines[final_from - 1 :]
    image = lines[final_from - 1].split()[1] if len(lines[final_from - 1].split()) > 1 else ""
    if "nonroot" in image.casefold():
        return
    users = [line.split(None, 1)[1].strip() for line in stage if re.match(r"(?i)\s*USER\s+\S", line)]
    if users and users[-1].split(":")[0].casefold() not in {"root", "0"}:
        return
    add("DOCKER-ROOT-001", final_from, 1, "final Docker stage", lines[final_from - 1])


def _redact(line: str, value: str) -> str:
    visible = value[:2] if len(value) > 6 else ""
    return line.replace(value, f"{visible}<redacted>", 1).strip()[:300]
