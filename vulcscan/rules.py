"""Rule catalog and deterministic remediation text.

Every rule the analyzers can emit is declared here with its CWE, category,
severity and remediation guidance. Concrete code suggestions come from
:mod:`vulcscan.patches`, never from this table.
"""

from __future__ import annotations

from dataclasses import dataclass

from .dataflow import (
    CODE,
    COMMAND,
    DESERIALIZATION,
    FILESYSTEM,
    HTML_OUTPUT,
    HTTP_REQUEST,
    REDIRECT,
    SQL,
    TEMPLATE,
    XML,
)
from .models import Confidence, Remediation, Severity


@dataclass(frozen=True, slots=True)
class RuleDefinition:
    rule_id: str
    name: str
    cwe: str
    category: str
    severity: Severity
    default_confidence: Confidence
    explanation: str


@dataclass(frozen=True, slots=True)
class Advice:
    title: str
    guidance: str
    confidence: Confidence
    risk: str


_FAMILIES: dict[str, tuple[str, str, str, Severity, str]] = {
    "CMD": (
        "OS Command Injection",
        "CWE-78",
        COMMAND,
        Severity.HIGH,
        "Untrusted input reaches a command interpreter or selects the executed program.",
    ),
    "SQL": (
        "SQL Injection",
        "CWE-89",
        SQL,
        Severity.HIGH,
        "Untrusted input becomes part of SQL text instead of a bound parameter.",
    ),
    "CODE": (
        "Code Injection",
        "CWE-94",
        CODE,
        Severity.CRITICAL,
        "Untrusted input reaches dynamic code evaluation.",
    ),
    "PATH": (
        "Path Traversal",
        "CWE-22",
        FILESYSTEM,
        Severity.HIGH,
        "Untrusted input reaches a filesystem path without a verified containment check.",
    ),
    "DESER": (
        "Unsafe Deserialization",
        "CWE-502",
        DESERIALIZATION,
        Severity.HIGH,
        "Untrusted data reaches a deserializer that can construct arbitrary objects.",
    ),
    "SSRF": (
        "Server-Side Request Forgery",
        "CWE-918",
        HTTP_REQUEST,
        Severity.HIGH,
        "Untrusted input controls the scheme or host of an outbound request.",
    ),
    "XSS": (
        "Cross-Site Scripting",
        "CWE-79",
        HTML_OUTPUT,
        Severity.HIGH,
        "Untrusted input reaches an HTML-producing sink without contextual output encoding.",
    ),
}

_TAINT_LANGUAGES: dict[str, tuple[str, ...]] = {
    "PY": ("CMD", "SQL", "CODE", "PATH", "DESER", "SSRF", "XSS"),
    "JS": ("CMD", "SQL", "CODE", "PATH", "DESER", "SSRF", "XSS"),
    "PHP": ("CMD", "SQL", "CODE", "PATH", "DESER", "SSRF"),
    "JAVA": ("CMD", "SQL", "PATH", "DESER", "SSRF", "XSS"),
    "CS": ("CMD", "SQL", "CODE", "PATH", "DESER", "SSRF", "XSS"),
    "GO": ("CMD", "SQL", "CODE", "PATH", "SSRF", "XSS"),
    "RB": ("CMD", "SQL", "CODE", "PATH", "DESER", "SSRF", "XSS"),
    "C": ("CMD", "SQL", "PATH"),
    "SH": ("CMD", "CODE"),
    "PS": ("CMD", "SQL", "CODE", "PATH", "SSRF"),
    "BAT": ("CMD", "CODE"),
}


def _definitions() -> dict[str, RuleDefinition]:
    rules: dict[str, RuleDefinition] = {}
    for prefix, families in _TAINT_LANGUAGES.items():
        for family in families:
            name, cwe, category, severity, explanation = _FAMILIES[family]
            rule_id = f"{prefix}-{family}-001"
            rules[rule_id] = RuleDefinition(
                rule_id, name, cwe, category, severity, Confidence.HIGH, explanation
            )
    for definition in (
        RuleDefinition(
            "PY-SSTI-001",
            "Server-Side Template Injection",
            "CWE-1336",
            TEMPLATE,
            Severity.HIGH,
            Confidence.HIGH,
            "Untrusted input becomes template source text.",
        ),
        RuleDefinition(
            "PY-XXE-001",
            "XML External Entity Processing",
            "CWE-611",
            XML,
            Severity.HIGH,
            Confidence.MEDIUM,
            "Untrusted XML reaches an lxml parser without an explicit hardened parser.",
        ),
        RuleDefinition(
            "OPEN-REDIRECT-001",
            "Open Redirect",
            "CWE-601",
            REDIRECT,
            Severity.MEDIUM,
            Confidence.HIGH,
            "Untrusted input controls the destination of a redirect.",
        ),
        RuleDefinition(
            "SECRET-001",
            "Hardcoded Credential",
            "CWE-798",
            "AUTH",
            Severity.HIGH,
            Confidence.MEDIUM,
            "A credential-like literal is assigned to a credential name.",
        ),
        RuleDefinition(
            "PRIVATE-KEY-001",
            "Embedded Private Key",
            "CWE-321",
            "AUTH",
            Severity.CRITICAL,
            Confidence.HIGH,
            "A PEM private key block with key material appears in a tracked file.",
        ),
        RuleDefinition(
            "TLS-VERIFY-001",
            "TLS Certificate Verification Disabled",
            "CWE-295",
            "CRYPTO",
            Severity.HIGH,
            Confidence.HIGH,
            "The client disables peer certificate or hostname verification.",
        ),
        RuleDefinition(
            "JWT-VERIFY-001",
            "JWT Signature Verification Disabled",
            "CWE-347",
            "AUTH",
            Severity.HIGH,
            Confidence.HIGH,
            "The token is decoded without verifying its signature or accepts the 'none' algorithm.",
        ),
        RuleDefinition(
            "WEAK-HASH-001",
            "Weak Password Hash",
            "CWE-916",
            "CRYPTO",
            Severity.HIGH,
            Confidence.MEDIUM,
            "Password data goes through a fast general-purpose digest instead of a password hash.",
        ),
        RuleDefinition(
            "WEAK-CIPHER-001",
            "Broken or Risky Cipher",
            "CWE-327",
            "CRYPTO",
            Severity.HIGH,
            Confidence.HIGH,
            "The code selects DES, 3DES, RC2, RC4, Blowfish or ECB mode.",
        ),
        RuleDefinition(
            "UNAUTH-ENCRYPTION-001",
            "Encryption Without Integrity",
            "CWE-353",
            "CRYPTO",
            Severity.HIGH,
            Confidence.MEDIUM,
            "The code encrypts attacker-controlled or security-sensitive data with a malleable mode and no nearby authentication check.",
        ),
        RuleDefinition(
            "WEAK-RANDOM-001",
            "Weak Security Randomness",
            "CWE-338",
            "CRYPTO",
            Severity.HIGH,
            Confidence.MEDIUM,
            "A security-sensitive value comes from a non-cryptographic random generator.",
        ),
        RuleDefinition(
            "TEMPFILE-001",
            "Insecure Temporary File",
            "CWE-377",
            "FILESYSTEM",
            Severity.MEDIUM,
            Confidence.HIGH,
            "tempfile.mktemp returns a name without creating the file, which allows a race.",
        ),
        RuleDefinition(
            "FILE-PERM-001",
            "World-Writable Permissions",
            "CWE-732",
            "FILESYSTEM",
            Severity.MEDIUM,
            Confidence.HIGH,
            "The code grants write permission to all users.",
        ),
        RuleDefinition(
            "DEBUG-001",
            "Debug Mode Enabled",
            "CWE-489",
            "CONFIGURATION",
            Severity.MEDIUM,
            Confidence.HIGH,
            "The configuration enables framework debug behavior.",
        ),
        RuleDefinition(
            "CORS-001",
            "Credentialed Cross-Origin Access From Any Origin",
            "CWE-942",
            "AUTH",
            Severity.HIGH,
            Confidence.HIGH,
            "The CORS configuration accepts any origin and allows credentials.",
        ),
        RuleDefinition(
            "XXE-001",
            "XML External Entity Processing",
            "CWE-611",
            XML,
            Severity.HIGH,
            Confidence.HIGH,
            "The XML parser enables DTD or external entity processing.",
        ),
        RuleDefinition(
            "DOCKER-ROOT-001",
            "Container Runs as Root",
            "CWE-250",
            "CONFIGURATION",
            Severity.LOW,
            Confidence.MEDIUM,
            "The final image stage does not switch to a non-root user.",
        ),
        RuleDefinition(
            "K8S-PRIV-001",
            "Privileged Container",
            "CWE-250",
            "CONFIGURATION",
            Severity.HIGH,
            Confidence.HIGH,
            "A container runs in privileged mode.",
        ),
        RuleDefinition(
            "BINARY-DANGEROUS-001",
            "Risky Native or Runtime API in Binary",
            "CWE-676",
            "BINARY",
            Severity.MEDIUM,
            Confidence.MEDIUM,
            "A compiled artifact imports or embeds a dangerous API name. Confirm reachability by disassembly.",
        ),
        RuleDefinition(
            "BINARY-HARDENING-001",
            "Missing Binary Exploit Mitigation",
            "CWE-693",
            "BINARY",
            Severity.MEDIUM,
            Confidence.HIGH,
            "The executable header explicitly lacks an operating-system exploit mitigation.",
        ),
        RuleDefinition(
            "BINARY-SECRET-001",
            "Credential Embedded in Binary",
            "CWE-798",
            "AUTH",
            Severity.HIGH,
            Confidence.MEDIUM,
            "A printable credential-like assignment is embedded in a compiled artifact.",
        ),
        RuleDefinition(
            "PHP-XSS-001",
            "Potential Cross-Site Scripting",
            "CWE-79",
            "OUTPUT_ENCODING",
            Severity.HIGH,
            Confidence.MEDIUM,
            "Dynamic PHP output reaches an HTML response without contextual output encoding.",
        ),
        RuleDefinition(
            "DB-RACE-001",
            "Non-Atomic Check-Then-Update",
            "CWE-362",
            "BUSINESS_LOGIC",
            Severity.HIGH,
            Confidence.MEDIUM,
            "A database value is checked and later decremented without an atomic predicate or transaction lock.",
        ),
        RuleDefinition(
            "SVG-ACTIVE-001",
            "Active Content in SVG",
            "CWE-79",
            "OUTPUT_ENCODING",
            Severity.HIGH,
            Confidence.HIGH,
            "An SVG asset contains script, an event handler or a javascript URL and may execute when served inline or opened directly.",
        ),
        RuleDefinition(
            "UPLOAD-MIME-001",
            "Unrestricted File Upload",
            "CWE-434",
            "FILE_UPLOAD",
            Severity.HIGH,
            Confidence.HIGH,
            "An upload is accepted using the client-declared MIME type instead of verified file content.",
        ),
        RuleDefinition(
            "CSRF-001",
            "Missing CSRF Protection",
            "CWE-352",
            "REQUEST_INTEGRITY",
            Severity.MEDIUM,
            Confidence.MEDIUM,
            "A PHP POST handler changes state without an apparent anti-CSRF token check.",
        ),
        RuleDefinition(
            "SESSION-FIXATION-001",
            "Session Identifier Not Rotated After Login",
            "CWE-384",
            "AUTH",
            Severity.MEDIUM,
            Confidence.HIGH,
            "Authentication state is stored in the session without regenerating its identifier.",
        ),
        RuleDefinition(
            "PHP-URL-INCLUDE-001",
            "Remote PHP Inclusion Enabled",
            "CWE-98",
            "CONFIGURATION",
            Severity.CRITICAL,
            Confidence.HIGH,
            "PHP allows URL-aware include and require operations, increasing remote file inclusion impact.",
        ),
        RuleDefinition(
            "CLEARTEXT-PASSWORD-001",
            "Cleartext Password Storage",
            "CWE-256",
            "AUTH",
            Severity.HIGH,
            Confidence.HIGH,
            "A password is seeded or stored as cleartext instead of a salted password hash.",
        ),
        RuleDefinition(
            "PHP-SSTI-001",
            "Twig Server-Side Template Injection",
            "CWE-1336",
            "TEMPLATE",
            Severity.HIGH,
            Confidence.MEDIUM,
            "An HTTP-controlled string is compiled directly into Twig template source using createTemplate.",
        ),
        RuleDefinition(
            "JS-SSTI-001",
            "Server-Side JavaScript Template Injection",
            "CWE-1336",
            "TEMPLATE",
            Severity.HIGH,
            Confidence.MEDIUM,
            "HTTP-controlled template source text is compiled or rendered by a server-side template engine instead of being passed as context data.",
        ),
        RuleDefinition(
            "JS-PROTOTYPE-001",
            "Prototype Pollution via Untrusted Object Merge",
            "CWE-1321",
            "OBJECT_INTEGRITY",
            Severity.HIGH,
            Confidence.MEDIUM,
            "A client-controlled object is merged into an existing object without verified dangerous-key filtering.",
        ),
        RuleDefinition(
            "C-ALLOC-001",
            "Unchecked Multiplication in C/C++ Allocation Size",
            "CWE-190",
            "MEMORY_SAFETY",
            Severity.HIGH,
            Confidence.MEDIUM,
            "A count originating from command-line input is multiplied by an element size for allocation without an identified overflow guard.",
        ),
        RuleDefinition(
            "C-BUFFER-001",
            "Potential C/C++ Buffer Overflow",
            "CWE-120",
            "MEMORY_SAFETY",
            Severity.HIGH,
            Confidence.MEDIUM,
            "An unbounded C input/copy primitive or unbounded copy of command-line data can write beyond a fixed destination buffer.",
        ),
        RuleDefinition(
            "JS-NOSQL-001",
            "NoSQL Query Operator Injection",
            "CWE-943",
            "SQL_EXECUTION",
            Severity.HIGH,
            Confidence.MEDIUM,
            "An entire HTTP-controlled object is passed directly to a MongoDB-style query method, allowing untrusted query operators or selectors.",
        ),
        RuleDefinition(
            "JS-TIMING-001",
            "Timing-Sensitive JavaScript Secret Comparison",
            "CWE-208",
            "AUTH",
            Severity.MEDIUM,
            Confidence.MEDIUM,
            "A direct HTTP field is compared with a secret-named value using ordinary JavaScript equality, which may disclose secret information through timing differences.",
        ),
        RuleDefinition(
            "PY-TIMING-001",
            "Timing-Sensitive Secret Comparison",
            "CWE-208",
            "AUTH",
            Severity.MEDIUM,
            Confidence.MEDIUM,
            "An HTTP-controlled value is compared to an authentication secret using == or !=. Timing-dependent comparison can disclose information about the secret.",
        ),
        RuleDefinition(
            "PY-TAR-EXTRACT-001",
            "Unfiltered TAR Archive Extraction",
            "CWE-22",
            "FILESYSTEM",
            Severity.HIGH,
            Confidence.MEDIUM,
            "An archive derived from an HTTP upload is extracted without a safe member/path filter. On affected Python runtimes this can allow archive entries to escape the destination directory.",
        ),
        RuleDefinition(
            "C-FORMAT-001",
            "Uncontrolled Format String",
            "CWE-134",
            "MEMORY_SAFETY",
            Severity.HIGH,
            Confidence.MEDIUM,
            "Potentially untrusted C/C++ data is used as a printf-family format string instead of a literal format such as %s.",
        ),
        RuleDefinition(
            "PY-ARG-001",
            "Argument Injection into External Program",
            "CWE-88",
            "COMMAND_EXECUTION",
            Severity.HIGH,
            Confidence.MEDIUM,
            "A network-controlled string is passed as a standalone argument to a command-line program that may interpret leading hyphens as options, despite shell=False.",
        ),
        RuleDefinition(
            "PHP-TYPE-JUGGLING-001",
            "Loose PHP Comparison of Authentication Values",
            "CWE-697",
            "AUTH",
            Severity.HIGH,
            Confidence.MEDIUM,
            "A loose comparison of an authentication value with user-controlled input can permit PHP type coercion and unexpected equality.",
        ),
        RuleDefinition(
            "AUTHZ-SCOPE-001",
            "Unscoped Resource Access",
            "CWE-639",
            "AUTH",
            Severity.HIGH,
            Confidence.MEDIUM,
            "A route loads a resource by a request identifier without an ownership or authorization scope in the same handler.",
        ),
        RuleDefinition(
            "ORM-EMPTY-AUTH-001",
            "Unchecked Empty ORM Authorization Result",
            "CWE-863",
            "AUTH",
            Severity.HIGH,
            Confidence.HIGH,
            "An ORM lookup can return no row without an error, then a zero-value identity reaches a privileged database operation.",
        ),
    ):
        rules[definition.rule_id] = definition
    return rules


RULES: dict[str, RuleDefinition] = _definitions()


def rule(rule_id: str) -> RuleDefinition:
    return RULES[rule_id]


_ALLOWLIST = Advice(
    "Validate the value against a strict allowlist at the input boundary.",
    "Accept only the finite set of identifiers or the character class the operation needs, "
    "and reject everything else before the sink.",
    Confidence.MEDIUM,
    "MEDIUM",
)

_FAMILY_ADVICE: dict[str, tuple[Advice, ...]] = {
    "CMD": (
        Advice(
            "Run the program without a shell and pass arguments as a list.",
            "Select the executable in trusted code and pass every user value as its own argument. "
            "Python: subprocess.run([program, arg, value]); Node.js: execFile(program, [arg, value]).",
            Confidence.HIGH,
            "MEDIUM",
        ),
        _ALLOWLIST,
    ),
    "SQL": (
        Advice(
            "Bind user values as query parameters.",
            "Keep the SQL text constant and pass values through the driver's parameter argument. "
            "Identifiers such as column names need an allowlist because drivers cannot bind them.",
            Confidence.HIGH,
            "LOW",
        ),
        Advice(
            "Use the ORM query API instead of raw SQL text.",
            "Express the filter with the ORM so values are bound by the library.",
            Confidence.MEDIUM,
            "MEDIUM",
        ),
    ),
    "CODE": (
        Advice(
            "Remove dynamic evaluation of input.",
            "Parse the expected data format (JSON, a number, a literal) and dispatch through an "
            "explicit mapping of allowed operations.",
            Confidence.MEDIUM,
            "MEDIUM",
        ),
    ),
    "PATH": (
        Advice(
            "Resolve the path and enforce base-directory containment.",
            "Canonicalize base and candidate (realpath/resolve), then reject the request unless "
            "the candidate stays inside the base directory.",
            Confidence.MEDIUM,
            "MEDIUM",
        ),
        Advice(
            "Reduce the input to a bare file name.",
            "Use basename/secure_filename when the caller only needs to pick a file inside one directory.",
            Confidence.MEDIUM,
            "LOW",
        ),
    ),
    "DESER": (
        Advice(
            "Use a data-only format for untrusted input.",
            "Replace native object deserialization with JSON plus schema validation.",
            Confidence.MEDIUM,
            "HIGH",
        ),
        Advice(
            "Authenticate serialized data before loading it.",
            "If native serialization must stay, sign the payload with an HMAC and verify it before deserializing.",
            Confidence.MEDIUM,
            "MEDIUM",
        ),
    ),
    "SSRF": (
        Advice(
            "Allowlist outbound destinations.",
            "Parse the URL, require an allowed scheme and an exact allowlisted host, and build the "
            "request from the validated parts.",
            Confidence.MEDIUM,
            "MEDIUM",
        ),
        Advice(
            "Fix the host in code and let input select only a path segment.",
            "Build the URL from a constant base such as https://api.example.com/ and URL-encode the user value.",
            Confidence.MEDIUM,
            "LOW",
        ),
    ),
    "XSS": (
        Advice(
            "Encode the value for its HTML context.",
            "Use the framework's contextual encoder and keep user input as template data. HTML text, attributes, URLs and JavaScript require different encoders.",
            Confidence.HIGH,
            "LOW",
        ),
        Advice(
            "Return structured JSON instead of HTML.",
            "For API endpoints, use the framework JSON response type and an application/json content type.",
            Confidence.MEDIUM,
            "LOW",
        ),
    ),
}

_RULE_ADVICE: dict[str, tuple[Advice, ...]] = {
    "PY-SSTI-001": (
        Advice(
            "Render a fixed template and pass input as context data.",
            "Keep template text in trusted files, e.g. render_template('page.html', value=value).",
            Confidence.HIGH,
            "LOW",
        ),
        Advice(
            "Use a sandboxed environment if users must author templates.",
            "jinja2.sandbox.SandboxedEnvironment limits attribute access; keep it up to date.",
            Confidence.LOW,
            "MEDIUM",
        ),
    ),
    "PY-XXE-001": (
        Advice(
            "Parse untrusted XML with a hardened parser.",
            "Use defusedxml, or lxml.etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False).",
            Confidence.HIGH,
            "LOW",
        ),
    ),
    "OPEN-REDIRECT-001": (
        Advice(
            "Allowlist redirect destinations.",
            "Accept only relative paths that start with a single '/', or map identifiers to server-owned URLs. "
            "Django provides url_has_allowed_host_and_scheme().",
            Confidence.MEDIUM,
            "LOW",
        ),
    ),
    "SECRET-001": (
        Advice(
            "Move the credential out of source control and rotate it.",
            "Read it from the environment or a secret manager at runtime; treat the committed value as exposed.",
            Confidence.HIGH,
            "MEDIUM",
        ),
    ),
    "PRIVATE-KEY-001": (
        Advice(
            "Remove the private key and rotate it.",
            "Revoke the key, issue a new one and store it in a secret manager; purge it from history.",
            Confidence.HIGH,
            "HIGH",
        ),
    ),
    "TLS-VERIFY-001": (
        Advice(
            "Keep certificate and hostname verification enabled.",
            "For a private CA, pass its bundle (requests: verify='/path/ca.pem') instead of disabling checks.",
            Confidence.HIGH,
            "LOW",
        ),
    ),
    "JWT-VERIFY-001": (
        Advice(
            "Verify the token signature with an explicit algorithm list.",
            "PyJWT: jwt.decode(token, key, algorithms=['RS256']); never accept 'none'.",
            Confidence.HIGH,
            "LOW",
        ),
    ),
    "WEAK-HASH-001": (
        Advice(
            "Store passwords with a password hashing function.",
            "Use Argon2id, scrypt, bcrypt or PBKDF2 with a per-user salt; rehash on next login.",
            Confidence.MEDIUM,
            "MEDIUM",
        ),
    ),
    "WEAK-CIPHER-001": (
        Advice(
            "Use an authenticated modern cipher.",
            "Use AES-GCM or ChaCha20-Poly1305 with a unique nonce per message; plan migration of stored data.",
            Confidence.MEDIUM,
            "HIGH",
        ),
    ),
    "UNAUTH-ENCRYPTION-001": (
        Advice(
            "Replace the malleable mode with authenticated encryption.",
            "Use AES-GCM, AES-EAX or ChaCha20-Poly1305 with a unique nonce. Reject the message before parsing when tag verification fails.",
            Confidence.MEDIUM,
            "HIGH",
        ),
    ),
    "AUTHZ-SCOPE-001": (
        Advice(
            "Scope the resource lookup to the authenticated principal.",
            "Include the owner, tenant or ACL predicate in the database lookup itself, then return 404 or 403 when no scoped row exists.",
            Confidence.MEDIUM,
            "MEDIUM",
        ),
    ),
    "ORM-EMPTY-AUTH-001": (
        Advice(
            "Reject an empty authorization lookup before using the model.",
            "For GORM Find, require RowsAffected greater than zero before reading identity fields. First or Take can instead handle gorm.ErrRecordNotFound explicitly.",
            Confidence.HIGH,
            "LOW",
        ),
    ),
    "WEAK-RANDOM-001": (
        Advice(
            "Generate the value with a cryptographic random source.",
            "Python: secrets.token_urlsafe(), secrets.choice(); Node.js: crypto.randomBytes(), crypto.randomUUID().",
            Confidence.HIGH,
            "LOW",
        ),
    ),
    "TEMPFILE-001": (
        Advice(
            "Create the temporary file atomically.",
            "Use tempfile.mkstemp() or tempfile.NamedTemporaryFile(), which create the file with safe permissions.",
            Confidence.HIGH,
            "LOW",
        ),
    ),
    "FILE-PERM-001": (
        Advice(
            "Remove world-write permission.",
            "Grant write access only to the owner or a dedicated group, e.g. 0o640 for files or 0o750 for directories.",
            Confidence.MEDIUM,
            "MEDIUM",
        ),
    ),
    "DEBUG-001": (
        Advice(
            "Disable debug mode outside development.",
            "Read the flag from configuration that defaults to false in deployed environments.",
            Confidence.HIGH,
            "LOW",
        ),
    ),
    "CORS-001": (
        Advice(
            "List trusted origins explicitly when credentials are allowed.",
            "Return Access-Control-Allow-Origin only for an exact allowlisted origin.",
            Confidence.HIGH,
            "LOW",
        ),
    ),
    "XXE-001": (
        Advice(
            "Disable DTD and external entity processing.",
            "Java: factory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true); "
            ".NET: DtdProcessing.Prohibit; PHP: do not pass LIBXML_NOENT.",
            Confidence.HIGH,
            "LOW",
        ),
    ),
    "DOCKER-ROOT-001": (
        Advice(
            "Run the final image as an unprivileged user.",
            "Create a fixed UID/GID and add USER after the steps that need root.",
            Confidence.MEDIUM,
            "MEDIUM",
        ),
    ),
    "K8S-PRIV-001": (
        Advice(
            "Remove privileged mode.",
            "Set privileged: false and grant only the specific capabilities the workload needs.",
            Confidence.HIGH,
            "MEDIUM",
        ),
    ),
    "BINARY-DANGEROUS-001": (
        Advice(
            "Replace the risky API and rebuild the artifact.",
            "Confirm the call by disassembly or symbols. Use bounded string functions and process APIs that do not invoke a shell.",
            Confidence.MEDIUM,
            "MEDIUM",
        ),
    ),
    "BINARY-HARDENING-001": (
        Advice(
            "Enable compiler and linker exploit mitigations.",
            "Rebuild with ASLR/PIE and NX/DEP enabled. For native code also enable stack protection, RELRO and control-flow protection where supported.",
            Confidence.HIGH,
            "MEDIUM",
        ),
    ),
    "BINARY-SECRET-001": (
        Advice(
            "Remove and rotate the embedded credential.",
            "Load the secret at runtime from a protected environment or secret store, then rebuild and rotate the exposed value.",
            Confidence.HIGH,
            "HIGH",
        ),
    ),
    "PHP-XSS-001": (
        Advice(
            "Encode dynamic values for their HTML context.",
            "Use htmlspecialchars(value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') for HTML text and attributes. Keep raw HTML out of stored user content.",
            Confidence.HIGH,
            "LOW",
        ),
    ),
    "DB-RACE-001": (
        Advice(
            "Make the state transition atomic.",
            "Use one conditional UPDATE such as UPDATE ... SET remaining = remaining - 1 WHERE ... AND remaining > 0, then require exactly one affected row. Use a transaction and row lock when several writes must commit together.",
            Confidence.HIGH,
            "MEDIUM",
        ),
    ),
    "SVG-ACTIVE-001": (
        Advice(
            "Remove active content from the SVG.",
            "Sanitize SVG uploads with a strict allowlist, remove scripts, event attributes, foreignObject and javascript URLs, and serve user SVG as an attachment from a separate origin.",
            Confidence.HIGH,
            "LOW",
        ),
    ),
    "UPLOAD-MIME-001": (
        Advice(
            "Verify file content and generate the destination name.",
            "Inspect bytes with finfo/Fileinfo, decode the expected image format, enforce size and dimensions, generate a random server-side name, and store outside executable paths.",
            Confidence.HIGH,
            "MEDIUM",
        ),
    ),
    "CSRF-001": (
        Advice(
            "Require a session-bound anti-CSRF token.",
            "Generate a cryptographically random token, store it in the session, include it in the form, and compare it with hash_equals before changing state. Use SameSite cookies as defense in depth.",
            Confidence.HIGH,
            "MEDIUM",
        ),
    ),
    "SESSION-FIXATION-001": (
        Advice(
            "Rotate the session identifier after authentication.",
            "Call session_regenerate_id(true) immediately after credential verification and before setting authenticated session state.",
            Confidence.HIGH,
            "LOW",
        ),
    ),
    "PHP-URL-INCLUDE-001": (
        Advice(
            "Disable URL includes.",
            "Set allow_url_include = Off. Keep include/require targets server-owned and allowlisted.",
            Confidence.HIGH,
            "LOW",
        ),
    ),
    "PHP-SSTI-001": (
        Advice(
            "Render fixed Twig templates instead of compiling request text.",
            "Keep template source in server-owned files and pass request fields only as escaped context values. Do not call Twig createTemplate with a string taken from GET or POST data.",
            Confidence.HIGH,
            "LOW",
        ),
    ),
    "JS-SSTI-001": (
        Advice(
            "Keep template source server-controlled.",
            "Use a fixed trusted template file and pass request input only as escaped context values. Do not compile or render req.body or req.query strings as EJS, Pug, Handlebars or Nunjucks template source.",
            Confidence.HIGH,
            "LOW",
        ),
    ),
    "JS-PROTOTYPE-001": (
        Advice(
            "Validate object keys and merge only explicit schema fields.",
            "Reject __proto__, prototype and constructor keys recursively; use a maintained safe-merge API or a schema that copies only expected fields. Avoid recursively merging req.body/req.query into application state or configuration.",
            Confidence.MEDIUM,
            "MEDIUM",
        ),
    ),
    "C-ALLOC-001": (
        Advice(
            "Check allocation-size multiplication before allocating.",
            "Before malloc(count * sizeof(element)), validate count against SIZE_MAX / sizeof(element) and reject multiplication overflow. For calloc, check its return value and use a standard-compliant implementation; verify the actual input bounds.",
            Confidence.MEDIUM,
            "MEDIUM",
        ),
    ),
    "C-BUFFER-001": (
        Advice(
            "Bound the write by the destination buffer size.",
            "Avoid gets and unbounded scanf %s; use fgets or a width-constrained format matched to the true buffer capacity. For copies from argv, validate the destination capacity, reserve space for the terminator, and prefer explicit bounds.",
            Confidence.MEDIUM,
            "MEDIUM",
        ),
    ),
    "JS-NOSQL-001": (
        Advice(
            "Construct a schema-validated query object.",
            "Select allowed fields and operators explicitly and validate scalar types before constructing a MongoDB/Mongoose filter. Do not pass req.body, req.query, or other client-controlled objects directly as selectors.",
            Confidence.HIGH,
            "MEDIUM",
        ),
    ),
    "JS-TIMING-001": (
        Advice(
            "Use constant-time secret verification where appropriate.",
            "For binary secret values, convert to validated equal-length Buffer values and compare with crypto.timingSafeEqual; reject length mismatches without introducing a variable-time prefix comparison. Passwords require an appropriate password-KDF verifier.",
            Confidence.MEDIUM,
            "MEDIUM",
        ),
    ),
    "PY-TIMING-001": (
        Advice(
            "Use constant-time verification for secret values.",
            "Compare verified, same-type secret bytes or strings with hmac.compare_digest. Use a password KDF verifier for passwords; do not replace ordinary non-secret equality tests.",
            Confidence.HIGH,
            "MEDIUM",
        ),
    ),
    "PY-TAR-EXTRACT-001": (
        Advice(
            "Enable safe TAR extraction filtering.",
            "On supported Python runtimes, pass filter=\"data\" to tarfile.extractall/extract and independently validate archive member names, links and destination containment. Test the exact Python runtime used in production before deploying a patch.",
            Confidence.MEDIUM,
            "MEDIUM",
        ),
    ),
    "C-FORMAT-001": (
        Advice(
            "Use a literal format string.",
            "Pass the input as a value, for example printf(\"%s\", value) or fprintf(stderr, \"%s\", value). Review buffer termination and encoding; never pass externally controlled text as the format argument.",
            Confidence.HIGH,
            "LOW",
        ),
    ),
    "PY-ARG-001": (
        Advice(
            "Validate or disambiguate external command arguments.",
            "For argument values taken from requests, enforce an allowlist appropriate to the selected program. Where supported, terminate option parsing with '--' before the untrusted positional value and do not allow the user to choose an option or subcommand.",
            Confidence.MEDIUM,
            "MEDIUM",
        ),
    ),
    "PHP-TYPE-JUGGLING-001": (
        Advice(
            "Use strict comparisons or a purpose-built credential verifier.",
            "Replace loose ==/!= checks with ===/!== for ordinary typed values. For secret hashes or MACs use hash_equals with verified string types; for password storage use password_verify. Confirm expected input types and regression-test authentication flows.",
            Confidence.HIGH,
            "MEDIUM",
        ),
    ),
    "CLEARTEXT-PASSWORD-001": (
        Advice(
            "Store only salted password hashes.",
            "Use password_hash with PASSWORD_ARGON2ID or PASSWORD_DEFAULT and verify with password_verify. Rotate seeded credentials.",
            Confidence.HIGH,
            "HIGH",
        ),
    ),
}


def advice_for(rule_id: str) -> tuple[Advice, ...]:
    if rule_id in _RULE_ADVICE:
        return _RULE_ADVICE[rule_id]
    family = rule_id.split("-")[1] if rule_id.count("-") >= 2 else ""
    return _FAMILY_ADVICE.get(
        family,
        (
            Advice(
                "Remove the unsafe data path.",
                "Validate at the trust boundary and use the safe form of the API.",
                Confidence.LOW,
                "MEDIUM",
            ),
        ),
    )


def remediations_for(
    rule_id: str,
    current: str | None = None,
    suggestion: Remediation | None = None,
) -> list[Remediation]:
    """Return the preferred fix followed by at most two alternatives.

    ``suggestion`` is a concrete, finding-specific patch from
    :mod:`vulcscan.patches`. When present it becomes the preferred fix and the
    first catalog entry becomes an alternative.
    """
    items: list[Remediation] = []
    if suggestion is not None:
        items.append(suggestion)
    for advice in advice_for(rule_id):
        items.append(
            Remediation(
                title=advice.title,
                guidance=advice.guidance,
                preferred=not items,
                patch_confidence=advice.confidence,
                patch_risk=advice.risk,
                current=current if not items else None,
            )
        )
    return items[:3]


def test_vectors_for(rule_id: str) -> list[str]:
    """Return fixed, non-destructive probes for an authorized test system."""
    family = rule_id.split("-")[1] if rule_id.count("-") >= 2 else ""
    vectors = {
        "CMD": [
            "Append `; printf VULCSCAN_PROBE` to a text parameter on a disposable test instance; success means shell metacharacters were interpreted.",
        ],
        "SQL": [
            "Use `' OR '1'='1' -- ` in the reported parameter with test data; compare the result with a normal invalid value.",
            "Use a single quote `'` and confirm the application neither changes query behavior nor exposes a database error.",
        ],
        "CODE": ["Submit `1+1` or another side-effect-free expression and verify that it is treated as text, not evaluated."],
        "PATH": [
            "Try `../../../../etc/hostname` on Linux or `..\\..\\..\\..\\Windows\\win.ini` on Windows in an isolated test deployment.",
            "For uploads, use the harmless name `../vulcscan-probe.txt` and benign text content; verify containment and rejection.",
        ],
        "DESER": ["Submit malformed or unexpected serialized type metadata with no executable gadget and verify strict rejection before object construction."],
        "SSRF": [
            "Start a controlled local listener, then submit `http://127.0.0.1:8000/vulcscan-probe`; any received request confirms server-side fetching.",
            "Also test alternate loopback spelling such as `http://2130706433:8000/vulcscan-probe` against the same controlled listener.",
        ],
    }
    if family == "XSS" or rule_id == "SVG-ACTIVE-001":
        return ["Submit `<img src=x onerror=alert('VULCSCAN_PROBE')>` as the reported field on a disposable account, then view the affected page in a test browser."]
    if rule_id == "PY-SSTI-001":
        return ["Submit `{{7*7}}`; rendering `49` instead of the literal text confirms template evaluation."]
    if rule_id == "OPEN-REDIRECT-001":
        return ["Submit `https://example.invalid/vulcscan-probe` and verify the response refuses an external Location target."]
    if rule_id == "DB-RACE-001":
        return ["Send two simultaneous requests using one disposable single-use coupon or token; exactly one must succeed and the stored counter must not become negative."]
    if rule_id == "BINARY-DANGEROUS-001":
        return ["Map the reported import to call sites with a disassembler, then exercise that path with boundary-length benign input under ASan, UBSan or Application Verifier."]
    if rule_id == "BINARY-HARDENING-001":
        return ["Confirm the header result with `checksec` for ELF or `dumpbin /headers` for PE; no exploit payload is needed."]
    if rule_id == "UPLOAD-MIME-001":
        return ["Upload benign text named `vulcscan-probe.php.jpg` while declaring `Content-Type: image/jpeg`; the server must reject it after inspecting the bytes."]
    if rule_id == "CSRF-001":
        return ["From a separate test origin, submit the same POST without a CSRF token; the application must reject it before changing state."]
    if rule_id == "SESSION-FIXATION-001":
        return ["Record a disposable test session ID before login and confirm that a different ID is issued immediately after successful authentication."]
    verification = {
        "PY-XXE-001": ["Parse `<!DOCTYPE x [<!ENTITY probe SYSTEM \"file:///vulcscan-nonexistent\">]><x>&probe;</x>` and confirm the parser rejects the DOCTYPE before resolving the entity."],
        "XXE-001": ["Parse `<!DOCTYPE x [<!ENTITY probe SYSTEM \"file:///vulcscan-nonexistent\">]><x>&probe;</x>` and confirm the parser rejects the DOCTYPE before resolving the entity."],
        "SECRET-001": ["Replace the reported value with a disposable canary credential, build the artifact, then search logs and packaged files for that canary; it must not appear."],
        "PRIVATE-KEY-001": ["Use a disposable test key, build the release artifact, then run `rg -n \"BEGIN .*PRIVATE KEY\" ARTIFACT_DIRECTORY`; no private key should be present."],
        "TLS-VERIFY-001": ["Point the client at a local HTTPS endpoint with a self-signed certificate; the connection must fail with certificate verification enabled."],
        "JWT-VERIFY-001": ["Submit the unsigned test token `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ2dWxjc2Nhbi1wcm9iZSJ9.`; the application must reject it before authorization."],
        "WEAK-HASH-001": ["Create two disposable accounts with the same test password and inspect their stored hashes; use a password KDF with unique salts, so the hashes must differ."],
        "WEAK-CIPHER-001": ["Encrypt repeated test blocks such as `VULCSCAN-PROBE!!VULCSCAN-PROBE!!`; ciphertext must not expose repeated blocks and authenticated decryption must reject one changed byte."],
        "UNAUTH-ENCRYPTION-001": ["Flip one bit in a disposable ciphertext, IV and authentication tag separately; authenticated decryption must reject every modified message before parsing plaintext."],
        "WEAK-RANDOM-001": ["Run the token generator twice with the same controlled PRNG seed; security tokens must not repeat or become predictable."],
        "TEMPFILE-001": ["In a disposable directory, pre-create the predicted temporary path as a symlink to another test file; the program must refuse the path and leave the target unchanged."],
        "FILE-PERM-001": ["Create the file in a disposable environment, then verify another unprivileged account cannot modify it; on Unix use `stat -c '%a %n' FILE`."],
        "DEBUG-001": ["Send a malformed request to the test deployment; the response must not contain a stack trace, source path, environment value or interactive debugger."],
        "CORS-001": ["Run `curl -i -H \"Origin: https://example.invalid\" -H \"Cookie: probe=1\" URL`; the response must not combine reflected or wildcard origin access with credentials."],
        "DOCKER-ROOT-001": ["Run `docker run --rm IMAGE id -u`; the result must be a non-zero UID used by the application process."],
        "K8S-PRIV-001": ["Inspect the rendered manifest with `kubectl create --dry-run=client -o yaml -f MANIFEST`; no container may request privileged mode or added dangerous capabilities."],
        "BINARY-SECRET-001": ["Run `strings BINARY` in an isolated workspace and search for the redacted credential label; production secrets must not appear in the executable."],
        "PHP-URL-INCLUDE-001": ["On an isolated PHP test instance, submit `data://text/plain,<?php echo 'VULCSCAN_PROBE'; ?>`; the include must reject the wrapper and must not print the marker."],
        "CLEARTEXT-PASSWORD-001": ["Export a disposable database row or seed artifact and confirm it contains a salted password-KDF hash, never the test password itself."],
        "PHP-SSTI-001": ["On a disposable test service, supply a harmless arithmetic marker such as {{7*7}} as the template field. The marker must be kept as data rather than compiled into Twig source."],
        "JS-SSTI-001": ["On a disposable instance, submit harmless template arithmetic like <%= 7*7 %> for EJS or {{7*7}} for supported engines. The input must remain data, not be rendered as a template."],
        "JS-PROTOTYPE-001": ["In an isolated test application, submit a harmless JSON object containing an unexpected __proto__ or constructor key; confirm the server rejects the key and no inherited property appears in subsequently constructed objects."],
        "C-ALLOC-001": ["With a disposable instrumented build, test small valid counts and an oversized synthetic count. The application must reject allocation-size overflow before allocating or copying data."],
        "C-BUFFER-001": ["Use a disposable debug build under ASan or UBSan and send boundary-length non-secret strings. Check that input is bounded to destination capacity and that any truncation preserves a valid terminator."],
        "JS-NOSQL-001": ["In a disposable test database, submit a harmless object with an unexpected MongoDB operator key such as $ne where a scalar is expected. The service must reject unsupported operators before querying."],
        "JS-TIMING-001": ["On an isolated test service, compare disposable tokens differing near the first and last character and review that the implementation uses a constant-time comparison for equal-length secret buffers. Do not probe live authentication endpoints."],
        "PY-TIMING-001": ["Use two disposable tokens of equal length differing at the first and last positions and review whether the code uses hmac.compare_digest; avoid timing experiments on production authentication endpoints."],
        "PY-TAR-EXTRACT-001": ["In a disposable directory, prepare a TAR containing an ordinary file with a `../` entry name and no sensitive content; the extractor must reject traversal or keep all writes strictly within the destination. Do not test against production files."],
        "C-FORMAT-001": ["On an isolated debug build, supply benign input containing literal format markers such as `%s` and `%x`. The program must print them as ordinary text and must not interpret them as format directives; use sanitizers for memory safety checks."],
        "PY-ARG-001": ["Use a disposable workspace and send a benign string beginning with a hyphen through the reported field. Confirm it is handled as data rather than an option; do not run the test against production repositories or accounts."],
        "PHP-TYPE-JUGGLING-001": ["On a disposable test instance compare synthetic token strings that PHP may coerce, such as `0e123` and `0e456`. Authentication must reject unequal tokens; verify strict comparison or hash_equals with strings."],
        "AUTHZ-SCOPE-001": ["Create one disposable resource as account A, then request the same identifier as account B. Any resource content or metadata in B's response proves missing object-level authorization."],
        "ORM-EMPTY-AUTH-001": ["Use a random nonexistent session token on the reported state-changing request. The service must reject it before inserting, updating or deleting a row; verify that no row with an empty owner or principal was created."],
    }
    return vectors.get(family, verification.get(rule_id, []))
