# VulcScan

VulcScan is a deterministic, rule-based static application security scanner (SAST). It analyzes a repository without running it and reports source-to-sink vulnerabilities, risky configuration, hardcoded secrets, compiled-artifact risks and vulnerable dependency versions. Each finding carries a CWE, severity, confidence, file, line and column, a patch location, deterministic remediation and safe test vectors when applicable.

It uses no AI or machine learning, has no runtime dependencies beyond the Python standard library, and never executes, imports or installs code from the scanned repository.

## Install

Requires Python 3.11 or newer.

### Windows (PowerShell)

```text
py -3.11 -m pip install --user .
vulcscan C:\path\to\service --offline
```

No virtual environment is required. If PowerShell cannot find `vulcscan` after installation, reopen the terminal so the per-user Python Scripts directory is reloaded into `PATH`.

### Linux

```text
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
vulcscan /path/to/service --offline
```

After installation, use `vulcscan PATH`. From a source checkout, `python -m vulcscan PATH` runs the same CLI.

## Usage

```text
vulcscan PATH [--offline|--update-cve] [--no-cve] [--format text|json] [--output FILE]
              [--severity CRITICAL|HIGH|MEDIUM|LOW|INFO] [--exclude PATTERN]
              [--max-file-size SIZE] [--patch-preview|--no-patch-preview] [--generate-diff FILE]
              [--color auto|always|never]
```

| Option | Effect |
| --- | --- |
| `--offline` | Keep network disabled. This is already the default; dependency CVEs are not reported. |
| `--update-cve` | Query OSV for this scan. Results stay in memory and are discarded when the command exits. |
| `--no-cve` | Skip dependency vulnerability lookup. |
| `--format json` | Machine-readable report on stdout (or in `--output`). Diagnostics go to stderr. |
| `--output FILE` | Write the report to a file; a `.json` suffix selects JSON. |
| `--severity LEVEL` | Show findings at or above LEVEL. |
| `--exclude PATTERN` | Repository-relative glob to skip; repeatable. |
| `--patch-preview` | Show current and suggested code when VulcScan can generate a concrete patch. Enabled by default. |
| `--no-patch-preview` | Hide current and suggested code snippets from text output. |
| `--generate-diff FILE` | Write a unified diff of machine-applicable fixes. Source files are never modified. |
| `--color MODE` | Color text output on terminals (`auto`, default), force ANSI colors, or disable them. `NO_COLOR` also disables color. |

On Windows, automatic color enables Virtual Terminal processing when stdout is a PowerShell console. Use `--color always` only when a terminal host is not detected correctly; redirected output and JSON remain uncolored.

Exit code 0 means the scan ran; 2 means a usage or fatal error.

Examples:

```text
vulcscan ./service --offline
vulcscan ./service --format json --output report.json
vulcscan ./service --offline --severity HIGH --patch-preview
```

## Output

The text report starts with scan counts and a one-line priority index. Detailed findings use separate `TRACE`, `RISK`, `VERIFY`, `FIX` and `REFERENCE` sections. Lines wrap at a readable terminal width, capped at 120 columns. Payloads, expected proof and patch previews keep hanging indentation, so PowerShell does not turn them into one paragraph. Findings remain sorted by severity, confidence, file and line. Dependency advisories use `D-001` identifiers. Parser and read problems appear under `Scan warnings`.

Paths in findings are relative to the scanned directory.

## Analysis support

| Language | Analysis | Confidence of traced flows |
| --- | --- | --- |
| Python | AST data flow: assignments, reassignment, f-strings, concatenation, comprehensions, branches, loops, try/with, function summaries, calls between functions and between modules of the repository, route parameters (Flask, FastAPI), sanitizers and guards | HIGH for network input, MEDIUM for CLI/stdin, LOW for environment variables |
| JavaScript, TypeScript | Statement parser with function and block scopes, `var` hoisting, destructuring, template literals, import/require aliases for `child_process`, `fs`, `vm`, HTTP clients; guards (allowlists, anchored regex tests, path containment) | as Python |
| PHP, Java, C#, Go, Ruby, C/C++, Shell, PowerShell, Batch | Logical statements (multi-line calls included), per-function scopes, framework sources (servlet, Spring, ASP.NET, gin/net/http, Rails, Laravel/Symfony), early-exit allowlist and containment guards | MEDIUM when traced through variables; a source written inside the sink call keeps its source confidence |
| Dockerfile, YAML, JSON, XML, SVG, CSS, `.env`, config files | Configuration, secret and active-SVG rules | rule-specific |
| PE, ELF, Mach-O, Java bytecode/JAR, WebAssembly and common native-library extensions | Magic/header inspection, PE ASLR/DEP, ELF PIE/NX stack, risky imported or embedded symbols and printable credential assignments | HIGH for explicit header flags, MEDIUM for symbol and string indicators |

Path traversal, SSRF, open redirect, template injection, XML and deserialization findings require network input: a CLI that opens the file named on its own command line is not reported.

Sanitizers are recognized by behavior, never by function name: numeric conversion, `shlex.quote`, `escapeshellarg`, `basename`/`secure_filename`, literal allowlists, anchored regex checks whose character class excludes dangerous characters (`re.fullmatch`, `\Z`; `re.match` with `$` is rejected because `$` accepts a trailing newline), and path containment checks on canonicalized paths. A function called `sanitize()` gets no trust.

### Rules

Source-to-sink: `<LANG>-CMD-001` (CWE-78), `-SQL-001` (CWE-89), `-CODE-001` (CWE-94), `-PATH-001` (CWE-22, includes upload `save()` with an unsanitized name), `-DESER-001` (CWE-502), `-SSRF-001` (CWE-918), `-XSS-001` (CWE-79 for Python, JavaScript/TypeScript, Java, C#, Go and Ruby), `PY-SSTI-001` (CWE-1336), `PY-XXE-001` (CWE-611), `OPEN-REDIRECT-001` (CWE-601). Prefixes: `PY`, `JS`, `PHP`, `JAVA`, `CS`, `GO`, `RB`, `C`, `SH`, `PS`, `BAT`. SQL injection tests cover vulnerable flows in Python, JavaScript/TypeScript, PHP, Java, C#, Go, Ruby, C/C++ and PowerShell, plus safe parameterized Python and JavaScript queries.

Pattern and configuration rules: `SECRET-001` hardcoded credential (CWE-798), `PRIVATE-KEY-001` (CWE-321), `TLS-VERIFY-001` (CWE-295), `JWT-VERIFY-001` (CWE-347), `WEAK-HASH-001` password digest (CWE-916), `WEAK-CIPHER-001` DES/3DES/RC4/ECB (CWE-327), `UNAUTH-ENCRYPTION-001` malleable encryption without integrity (CWE-353), `WEAK-RANDOM-001` (CWE-338), `AUTHZ-SCOPE-001` object lookup without principal scope (CWE-639), `ORM-EMPTY-AUTH-001` empty ORM authorization result used as identity (CWE-863), `TEMPFILE-001` (CWE-377), `FILE-PERM-001` world-writable (CWE-732), `DEBUG-001` (CWE-489), `CORS-001` credentialed origin reflection (CWE-942), `XXE-001` (CWE-611), `PHP-XSS-001` and `SVG-ACTIVE-001` (CWE-79), `UPLOAD-MIME-001` (CWE-434), `CSRF-001` (CWE-352), `SESSION-FIXATION-001` (CWE-384), `PHP-URL-INCLUDE-001` (CWE-98), `CLEARTEXT-PASSWORD-001` (CWE-256), `DB-RACE-001` (CWE-362), `DOCKER-ROOT-001` and `K8S-PRIV-001` (CWE-250). Binary rules cover risky APIs (`BINARY-DANGEROUS-001`, CWE-676), missing exploit mitigations (`BINARY-HARDENING-001`, CWE-693) and embedded credentials (`BINARY-SECRET-001`, CWE-798).

## Test vectors

Findings include non-destructive proof probes computed from the recovered source-to-sink flow, language, syntax context, reported sink and platform. Text reports print them under `Test vector`; JSON exposes `test_vectors`. SQL findings recover query shape and output-column count to produce row-scope and read proofs; command, XSS, path, SSRF, deserialization, code-evaluation, upload and redirect findings use family-specific canary payloads. Use them only on systems you own or are authorized to test, preferably with disposable data.

## Patch guidance

Every finding has a preferred fix and up to two alternatives with patch confidence and risk. For recoverable flows, VulcScan derives the patch from the actual variables, sink call, query or command shape, path base and framework API. SQL patches reconstruct simple concatenated queries across supported languages, bind the recovered values in order and preserve `LIKE` wildcards. Other rules receive concrete review patches for configuration, secrets, CSRF, races, sessions, uploads and password storage. A patch remains review-only when imports, types, framework state or policy cannot be proven; `--generate-diff` includes only verified exact rewrites.

## Dependencies and CVE lookup

Parsed formats: `requirements*.txt` (and `requirements/*.txt`), `pyproject.toml`, `poetry.lock`, `Pipfile`, `Pipfile.lock`, `package.json`, `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, `composer.json`, `composer.lock`, `pom.xml`, `build.gradle(.kts)`, `go.mod` (with `replace`), `go.sum`, `Gemfile`, `Gemfile.lock`, `packages.config`, `*.csproj`, `Directory.Packages.props`, `packages.lock.json`, `Cargo.toml`, `Cargo.lock`.

A lockfile version wins over manifest constraints of the same project. Exact pins (`==1.2.3`, an exact npm version) count as resolved. Only resolved versions are looked up. Git, path and workspace packages are not looked up.

OSV decides which advisories affect the version. VulcScan shows only the fixed version of the advisory range that contains the installed version; when it cannot place the version in a range, it lists the advisory's fixed versions with a note. It never makes up a fixed version.

## Network behavior

`vulcscan/cve.py` is the only module that imports networking code. Online scans send `POST https://api.osv.dev/v1/querybatch` with ecosystem, package name and version, and `GET https://api.osv.dev/v1/vulns/{id}` for advisory details. No source code, findings, paths or other repository data leave the machine; private package names do reach OSV.

Every URL must be HTTPS, host exactly `api.osv.dev`, port 443, one of those two paths, no query string or credentials. Redirects are refused, system proxies are ignored, certificates are verified against the platform trust store, the timeout is 8 seconds with one retry, and responses are capped at 16 MiB. VulcScan keeps OSV responses only in memory for the current command. It creates no CVE cache.

Network is disabled by default. Offline scans return zero dependency CVEs. Only `--update-cve` permits the allowlisted OSV requests described above. There is no telemetry, general web search, update check or crash reporting.

## Security model

The scanned repository is treated as hostile. VulcScan reads files as bytes, parses Python with `ast.parse` and everything else with its own text scanners, parses XML manifests only after rejecting DTDs, and never imports target modules or runs `setup.py`, package scripts, build tools or binaries. Symlinks and Windows junctions are not followed. Recognized binaries are inspected as bytes. Unknown binary formats, files over `--max-file-size` (default 2 MiB) and minified bundles are skipped. A file that fails to parse is reported as a scan warning; the scan continues.

## Known limitations

- Python cross-module flows need a direct call to an imported function; dynamic dispatch, decorators that wrap handlers, `getattr` and callbacks are not followed.
- JavaScript/TypeScript analysis stays within one file and does not follow higher-order functions or object properties set elsewhere.
- PHP, Java, C#, Go, Ruby, C/C++, Shell, PowerShell and Batch have no type information or inter-procedural analysis.
- Django literal `path`/`re_path` declarations are linked to imported function views; dynamic URL configuration and class-based `as_view()` dispatch are not resolved.
- Argument injection into a fixed program (`subprocess.run(["git", user_value])`) is not reported.
- Binary analysis is header, symbol and printable-string based. It does not replace disassembly, control-flow analysis, fuzzing or memory-safety instrumentation.
- Without `--update-cve`, dependency vulnerabilities are not reported. Corporate proxies are not supported for OSV lookups.
- Reported findings are potential vulnerabilities; a reviewer must confirm them.
- Object-level authorization analysis covers direct Express route lookups and intra-function GORM identity lookups. Indirect policy engines, helper guards and cross-service ownership checks remain outside its proof model.

## Tests

```text
python -m pip install -e ".[test]"
python -m pytest
```

The suite covers vulnerable and safe fixtures, malformed input, CRLF, paths with spaces, binary and oversized files, symlink handling, deterministic ordering, offline network denial, dependency formats, OSV range selection, exact diff safety and zero-AI/network-import audits. Guidance tests use unrelated synthetic services in Python, JavaScript, TypeScript, Java, C#, Go, Ruby and PHP and reject generic placeholders when flow symbols can be recovered.


### Opt-in endpoint inventory and remote-input filtering

Use `--attack-surface` to add an `attack_surface` array to JSON report **metadata**.
It statically inventories literal Flask/FastAPI-style decorator paths and direct
Express `app/router.METHOD('path', ...)` calls, with HTTP methods, file, line,
handler (where identifiable), authentication indicator, and conservative Python
finding-rule references. `authentication: "unknown"` does **not** imply no
authentication: middleware, dependencies, and imported wrappers are not fully
resolved. Dynamic routes are intentionally omitted; the inventory is not exhaustive.

Use `--remote-only` to exclude findings unless their SOURCE flow explicitly
mentions HTTP/network input. This is a conservative **triage filter**, not a
proof of exploitability and not an exhaustive list of reachable vulnerabilities.
Both options are off by default, preserving the existing standard JSON envelope:

```bash
python -m vulcscan ./service --offline --no-cve --attack-surface --format json
python -m vulcscan ./service --offline --no-cve --remote-only
```


### Rule-scoped Python suppressions

For a reviewed Python false positive, add an explicit exact-rule directive:

```python
dangerous_looking_call()  # vulcscan:ignore PY-CMD-001
# vulcscan:ignore PY-CMD-001
dangerous_looking_call()
```

An inline comment affects its own line; a standalone comment affects only
the following physical line. The rule ID must match exactly, no wildcard
suppression is supported, and directives inside strings are ignored. This
only filters findings, not detection or source execution. Use sparingly and
document why the finding is a false positive.

### Endpoint canaries and isolated patch validation

With `--attack-surface`, a Python GET endpoint associated with a traced literal query parameter may include a `verify_curl` field. The displayed command targets `127.0.0.1:8000` using the inert `VULCSCAN_CANARY` marker. It is never executed; no command is emitted for POST, dynamic routes or ambiguous inputs. Review handler behavior before running any GET request, because an application may incorrectly mutate state on GET.

Python `--generate-diff` validates proposed changes independently, so one invalid patch no longer discards unrelated valid edits. Syntax validation and basic import checks do not prove functional or SLA safety.

### Express handler links

With `--attack-surface`, unambiguous direct Express route handlers imported through relative ESM or CommonJS imports can be linked to their file and associated findings. This is endpoint correlation, not cross-module taint analysis. Dynamic imports, external modules, middleware chains, and ambiguous paths remain unresolved.

When `--attack-surface` is enabled in text mode, endpoints are printed before the finding priority index, including available handler links, rules, and loopback verification commands. Defaults are unchanged.

### Optional test-source noise filter

Use `--exclude-tests` to skip common test and fixture directories (`test`, `tests`, `__tests__`, `spec`, `specs`, `fixtures`, `__fixtures__`) and recognizable test file names (`test_*.py`, `*_test.go`, `*.test.js/ts`, `*.spec.js/ts` and JSX/TSX variants, plus `conftest.py`). This option is **off by default** so that existing coverage and dependency discovery remain unchanged. An opt-in filtered scan can miss vulnerabilities in executable fixtures or test helpers; use a complete scan when completeness matters. Production migrations and seed files are not excluded merely for having those names.

### Conservative one-hop JavaScript/TypeScript sink propagation

Directly imported, locally exported named functions whose **entire body** is one direct sink call (for example `function run(value) { cp.exec(value); }`) now allow a source at the call site to be traced to the sink across one ESM/CommonJS module boundary. Initial sink families are command execution (`exec`/`execSync`), file reads (`readFile`/`readFileSync`), `fetch`, and `eval`. The new finding retains caller source evidence, adds the callee sink location, and uses **MEDIUM** confidence. Literal/sanitized arguments, ambiguous module paths, external dependencies, shadowed identifiers, guarded or transformed wrappers and deeper call chains are not inferred. This is a deliberately bounded analysis, not complete JavaScript or TypeScript interprocedural analysis.

### JavaScript and TypeScript inline suppressions

A JavaScript or TypeScript finding may be suppressed with an exact-rule `// vulcscan:ignore JS-CMD-001` comment. A trailing comment affects only its own physical line; a standalone line comment affects only the next physical line. Comments inside strings, template literals, regular expressions, or `/* ... */` blocks are ignored; wildcard rules and global file suppressions are not supported. This feature is opt-in through the source comment and preserves the existing Python `# vulcscan:ignore RULE-ID` behavior. Suppress only verified false positives.

### PHP authentication comparisons and token signatures

The static rule `PHP-TYPE-JUGGLING-001` detects selected PHP `==`/`!=` comparisons between authentication-related variables and explicitly tracked request superglobal values. It recommends strict typed comparisons or `hash_equals`/`password_verify` as appropriate and never generates an automatic patch. Detection is intentionally conservative and does not prove a bypass. Secret signature matching now recognizes common `sk-proj-`, `sk-ant-`, `hf_`, `npm_` and `pypi-` prefixes without exposing the complete value in reports. These are string signatures, not proof that a credential is active; example files remain excluded from known-token alerts.

### Python argument injection without a shell

`PY-ARG-001` detects a narrowly scoped CWE-88 pattern: an explicit HTTP request value used as a positional argument in a literal list passed to `subprocess.run`, `subprocess.check_output`, `subprocess.check_call`, `subprocess.call`, `subprocess.Popen`, or `asyncio.create_subprocess_exec` for recognized external programs such as `git`, `tar`, `curl`, `ssh`, `rsync`, `find`, `openssl`, and `scp`. This is distinct from shell command injection: external programs may interpret untrusted values beginning with `-` as command-line options even when `shell=False`. Variables assigned from direct request parameters are traced within the same function; numeric casts, explicit `--` terminators, nonliteral executable names, and CLI-only values are not treated as this pattern. Findings are MEDIUM confidence, review-only, with a non-destructive verification description. No patch is applied or target code executed.

### C/C++ uncontrolled format strings

`C-FORMAT-001` (CWE-134) is a conservative review-only rule for `printf`, `fprintf`, and `syslog` when the format argument is directly `argv[n]` or a nearby variable filled by `argv[n]`, `fgets`, `recv` or `read`. Passing user input as an ordinary value with a literal format (`printf("%s", value)`) is not reported. As this is static pattern matching rather than a C/C++ compiler, findings use MEDIUM confidence and may need a source review; no source code is modified or executed.

### TAR extraction of HTTP uploads

`PY-TAR-EXTRACT-001` identifies an HTTP-derived TAR archive passed to Python `tarfile.open` and subsequently extracted with `extractall` or `extract` without an explicit extraction filter. For older Python runtimes, unfiltered archive members can escape the target directory or contain unsafe links. On modern runtimes the default behavior can differ; this is a **MEDIUM-confidence, review-only, runtime-dependent check**, not proof of exploitability. Using an explicit safe `filter="data"` or custom filter causes the analyzer to abstain. Trusted local TARs and `zipfile.extractall` are deliberately not blanket-flagged. No archive is extracted or executed during analysis.

### Timing-sensitive Python secret comparisons

`PY-TIMING-001` (CWE-208) is a conservative review-only check for direct HTTP request values compared using `==` or `!=` to authentication secrets (`token`, `hmac`, `signature`, `api_key`, etc.), including simple same-function assignments. It does not report normal username/numeric equality, `hmac.compare_digest`, or values overwritten before the comparison. The rule does not claim to measure actual timing leakage: review secret types, choose `hmac.compare_digest` for equal-type secrets, and use password-KDF verification for passwords. No target code is executed or automatically modified.

### NoSQL filter injection for JS/TS

`JS-NOSQL-001` (CWE-943) identifies a whole HTTP query or body object flowing into a recognized MongoDB/Mongoose method such as `User.find(req.body)` or `collection.findOne(filter)` after a direct `filter = req.query` assignment. It deliberately avoids flagging structured filters built with explicitly named fields, unrelated JavaScript collection methods, and numeric conversions. Findings retain source-to-sink flow and MEDIUM confidence and require manual review; the scan never executes the target application or applies a patch.

### Classic C/C++ unbounded buffer writes

`C-BUFFER-001` (CWE-120) identifies a narrow set of potentially unbounded writes: `gets(buffer)`, bare `scanf("%s", buffer)` without an explicit field width, and direct `strcpy`/`strcat`/`sprintf` copies from `argv[n]` into a destination. Width-bounded formats, `fgets`, and constant-string copies are not automatically flagged. This review-only lexical rule is not a substitute for compiled analysis; findings are MEDIUM confidence and should be assessed with test binaries and memory sanitizers. No application is run or automatically patched.

### ELF dynamic hardening without execution

For well-formed ELF32/ELF64 dynamic binaries, VulcScan now reads bounded program headers and dynamic string tables with Python's standard `struct` module. It distinguishes absent and partial RELRO (GNU_RELRO without BIND_NOW) from full RELRO, and flags clearly unsafe RPATH/RUNPATH entries such as empty, current-directory, relative paths, or temporary folders. A common `$ORIGIN/lib` or absolute system path is not automatically labeled unsafe. Malformed, truncated and static binaries are not guessed. Findings appear under `BINARY-HARDENING-001`; no binary is executed or loaded. This is a conservative hardening audit, not a complete ELF loader or checksec replacement.

### Offline OSV snapshot (opt-in)

Use `--cve-db FILE` to consume a local, preprepared OSV JSON snapshot with the network disabled:

    python -m vulcscan ./service --offline --cve-db ./osv-snapshot.json

The UTF-8 JSON must be an object with `format: "vulcscan-osv-v1"` and an `entries` array. Each entry supplies `ecosystem` (OSV ecosystem, e.g. `PyPI`), `name`, exact `version`, and an `advisories` array containing full OSV advisory JSON objects with `id` and `affected` package version/range data. For example, a PyPI package named `examplepackage` at version `1.0.0` may have an advisory for the range introduced at `0` and fixed at `2.0.0`. The client requires both an exact ecosystem/name/version entry and evidence that the advisory actually affects the installed version.

Snapshots are limited to 16 MiB; symbolic-link snapshots are rejected. No database is fetched or written automatically. `--cve-db` cannot be combined with `--update-cve` or `--no-cve`. Without the flag, offline scans continue to skip CVE results. The live `--update-cve` mode retains its old in-memory behavior. This is offline DB consumption, not a cache generator.

### JS/TS prototype pollution object merges

`JS-PROTOTYPE-001` (CWE-1321) reports direct use of an HTTP-supplied object such as `req.body` or `req.query` as the second argument of `Object.assign`, `_.merge`, `lodash.merge`, or `lodash.defaultsDeep`, including a simple local assignment. The recommended remediation is explicit schema validation and rejection of dangerous keys such as `__proto__`, `constructor` and `prototype` before merging. It deliberately abstains for explicitly enumerated fields and unrelated merge functions. MEDIUM-confidence findings are review-only and do not prove that application state can be poisoned. No target code is executed or patched.

### C/C++ allocation-size overflow

`C-ALLOC-001` (CWE-190) reviews malloc size multiplications where the count comes directly from CLI input via atoi/atol/strtoul. A recognized SIZE_MAX division guard or overwritten count prevents the alert. This is conservative lexical detection, not proof of exploitability or an automated patch.

### Deterministic per-file parallel analysis

Use `--workers N` with `N` from 1 to 8 to analyze independent source files and binaries concurrently (default `1`, preserving existing behavior). Python cross-module flow analysis and dependency discovery remain ordered and sequential. Results are collected in discovery order before normal sorting; the report content is equivalent to the serial scan aside from `scan_duration`. Execution uses Python's standard-library thread pool and never runs target code. Thread scheduling and the GIL mean a speedup is workload dependent, not guaranteed.

### Entropy-aware generic secret confidence

Generic secret literals under credential-like identifiers now use Shannon entropy to calibrate confidence: long (16+ character) highly repetitive values below 2.5 bits/character remain reported but are classified MEDIUM instead of HIGH confidence. Random-looking generic credential strings remain HIGH confidence, as do recognizable known-token prefixes. No finding is suppressed purely because of low entropy; long weak passwords and tokens still merit review. This is an ordering heuristic, not a test of cryptographic key strength.

### Structural PE import parsing

For well-formed PE32 and PE32+ images, VulcScan now reads DLL import descriptors, thunk tables and named Import Directory entries using bounded `struct` parsing. `BINARY-DANGEROUS-001` is based on the actual imported function name instead of arbitrary ASCII occurrences elsewhere in the binary, reducing false positives from embedded strings. For malformed or unsupported PE metadata, the previous byte-level heuristic remains as a fallback. Ordinal imports are not guessed as named symbols. This is a conservative ordinary-import parser, not full coverage of delay imports or runtime dynamic loading, and it never loads a DLL or executes the binary.

### Node.js secret equality timing checks

`JS-TIMING-001` (CWE-208) recognizes direct JavaScript/TypeScript comparisons (`==`, `!=`, `===`, `!==`) between a request field such as `req.body.token` or `req.headers.signature` and a secret-named identifier. Source-to-sink evidence makes it compatible with `--remote-only`. Prefer validated equal-length Buffers and `crypto.timingSafeEqual` where appropriate; passwords require a password-KDF verifier. This rule does not measure real timing differences or infer values through unresolved intermediates; it is conservative and review-only.

### ELF dynamic symbol import table

For structurally valid ELF32 and ELF64 section tables, VulcScan now reads undefined imports from `.dynsym` linked to `.dynstr` instead of treating every ASCII occurrence of dangerous API names as an imported function. It skips defined symbols, rejects truncated or invalid tables, and keeps the legacy byte heuristic as a fallback when the structural table is missing or unsupported. This is a bounded, execution-free import audit, not a complete ELF dynamic-loader emulator.

### Flask/FastAPI object authorization scope

`AUTHZ-SCOPE-001` now includes a bounded Python AST heuristic for Flask/FastAPI routes with path identifiers such as `/users/<int:user_id>` and `/accounts/{account_id}` used directly in `Model.query.get(id)`, `get_or_404`, or `db.session.get(Model, id)` calls. A recognizable owner/tenant filter or explicit authorization/ownership check in the same handler makes the analyzer abstain. Authentication decorators alone do not prove object-level authorization. Findings retain an HTTP route SOURCE and ORM SINK, including compatibility with `--remote-only`; they are MEDIUM-confidence and review-only, not proof of IDOR exploitation.

### Node.js server-side template injection

`JS-SSTI-001` (CWE-1336) traces direct HTTP-sourced strings into template **source** APIs: `ejs.render`/`ejs.compile`, `pug.render`/`pug.compile`, `Handlebars.compile` and `nunjucks.renderString`. User data passed as context to a fixed trusted template is not reported. Findings include HTTP SOURCE and template compilation SINK and work with `--remote-only`. This is conservative, MEDIUM-confidence, review-only analysis; it does not execute the application or infer arbitrary aliased template engines.

### PHP Twig template-source injection

`PHP-SSTI-001` (CWE-1336) identifies direct HTTP GET/POST/REQUEST values, or simple variable aliases assigned from them, passed to `$twig->createTemplate(...)` for compilation as Twig template source. It deliberately does not flag rendering a fixed template with request fields supplied as context. Long call chains, custom engines and unknown transforms are not inferred. Findings are MEDIUM-confidence review-only guidance and do not execute PHP or apply patches.
