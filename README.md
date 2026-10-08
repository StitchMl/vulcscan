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

Pattern and configuration rules: `SECRET-001` hardcoded credential (CWE-798), `PRIVATE-KEY-001` (CWE-321), `TLS-VERIFY-001` (CWE-295), `JWT-VERIFY-001` (CWE-347), `WEAK-HASH-001` password digest (CWE-916), `WEAK-CIPHER-001` DES/3DES/RC4/ECB (CWE-327), `UNAUTH-ENCRYPTION-001` malleable encryption without integrity (CWE-353), `WEAK-RANDOM-001` (CWE-338), `AUTHZ-SCOPE-001` object lookup without principal scope (CWE-639), `TEMPFILE-001` (CWE-377), `FILE-PERM-001` world-writable (CWE-732), `DEBUG-001` (CWE-489), `CORS-001` credentialed origin reflection (CWE-942), `XXE-001` (CWE-611), `PHP-XSS-001` and `SVG-ACTIVE-001` (CWE-79), `UPLOAD-MIME-001` (CWE-434), `CSRF-001` (CWE-352), `SESSION-FIXATION-001` (CWE-384), `PHP-URL-INCLUDE-001` (CWE-98), `CLEARTEXT-PASSWORD-001` (CWE-256), `DB-RACE-001` (CWE-362), `DOCKER-ROOT-001` and `K8S-PRIV-001` (CWE-250). Binary rules cover risky APIs (`BINARY-DANGEROUS-001`, CWE-676), missing exploit mitigations (`BINARY-HARDENING-001`, CWE-693) and embedded credentials (`BINARY-SECRET-001`, CWE-798).

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
- Django view parameters from URL patterns are not treated as sources.
- Argument injection into a fixed program (`subprocess.run(["git", user_value])`) is not reported.
- Binary analysis is header, symbol and printable-string based. It does not replace disassembly, control-flow analysis, fuzzing or memory-safety instrumentation.
- Without `--update-cve`, dependency vulnerabilities are not reported. Corporate proxies are not supported for OSV lookups.
- Reported findings are potential vulnerabilities; a reviewer must confirm them.
- Object-level authorization analysis covers direct Express route lookups. Indirect policy engines and cross-service ownership checks remain outside its proof model.

## Tests

```text
python -m pip install -e ".[test]"
python -m pytest
```

The suite covers vulnerable and safe fixtures, malformed input, CRLF, paths with spaces, binary and oversized files, symlink handling, deterministic ordering, offline network denial, dependency formats, OSV range selection, exact diff safety and zero-AI/network-import audits. Guidance tests use unrelated synthetic services in Python, JavaScript, TypeScript, Java, C#, Go, Ruby and PHP and reject generic placeholders when flow symbols can be recovered.
