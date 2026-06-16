# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
[Semantic Versioning](https://semver.org/).

## [0.15.0] - 2026-06-16

### Added
- **Spring Boot 2 / Java EE (`javax.*`) support** — `javax.persistence` `createQuery`
  / `createNativeQuery` and `javax.servlet` `sendRedirect` / `getParameter` /
  `getHeader` / `getQueryString`, alongside the `jakarta.*` signatures, so the
  analyzer works on Boot 2 apps (still widely deployed), not only Boot 3.
- **Map-typed sources** — a `Map.get` / `getOrDefault` taint transfer, so a tainted
  `@RequestParam Map<String,String>` propagates to values read out of it (a common
  real-world binding). Benchmark gains a Map case (now 35 vulnerable, 34 by the taint
  engine alone; 0 false positives).

### Validated
- These two additions were driven by, and verified against, a real vendor app:
  `Contrast-Security-OSS/vulnerable-spring-boot-application` (Spring Boot 2, `javax`,
  `@RequestParam Map`). The analyzer now finds its cross-layer SQL injection. See
  [docs/validation.md](docs/validation.md).

## [0.14.0] - 2026-06-16

### Added
- **Autofix now covers XSS** in addition to SQL injection: it wraps the interpolated
  values written to the response in `HtmlUtils.htmlEscape(...)` (adding the import).
  Verified end-to-end — applying the SQL + XSS fixes compiles cleanly and drops the
  benchmark's xss findings from 12 to 4 (the rest are cross-method/non-concat sinks).
- **Baseline mode** — `scan --baseline <file>` records the current findings on the
  first run, then on later runs reports (and gates CI on) only findings *not* in the
  baseline. Lets a team adopt the tool on a legacy codebase and fail the build only on
  new issues. Fingerprints are line-independent, so they survive code moving around.

## [0.13.0] - 2026-06-16

### Added
- A unit-test suite for the scanners (autofix, near-miss, config audit, config
  validator, secrets, misconfig), including regression tests for the v0.12.1 fixes
  (cross-method variable scoping, ambiguous file names, sensitive-getter false
  positive, cross-method escaped variable). Test count went from 2 to 18; an
  in-memory Java compiler builds bytecode fixtures for the ASM-based scanners.

### Fixed
- The bytecode scanners (`secrets`, `misconfig`) now read class files from any
  modern JDK. ASM was bumped 9.4 → 9.7; 9.4 threw "Unsupported class file major
  version 65" on Java 21+ bytecode, so the "any JDK" claim now actually holds. (The
  taint `scan` still needs JDK 17 — that is a separate Tai-e frontend limitation.)

## [0.12.1] - 2026-06-16

### Fixed
Correctness fixes from an internal code review (edge cases the single-package
benchmark did not exercise, but real multi-package projects would):
- **Inner/anonymous classes** — flow locations used `Foo$1.java`, which does not
  exist, so suppression, near-miss and autofix silently skipped findings inside
  nested classes. The `$…` suffix is now stripped.
- **Autofix could rewrite the wrong file** when two classes share a simple name in
  different packages; ambiguous file names are now skipped. The variable lookup is
  also scoped to the sink's own method (it could previously pick a same-named
  variable from another method).
- **`misconfig` false positive** — a sensitive getter used for a non-logging purpose
  (e.g. `encoder.matches(input, user.getPassword())`) no longer taints a later,
  unrelated log call.
- **Near-miss false positive** — an HTML-escaped variable in one method no longer
  triggers a wrong-context finding on a same-named variable in another method.
- **Secrets** — `@Value` defaults that are themselves references/SpEL
  (`${…}`, `#{…}`) are no longer flagged as literal secrets.
- `validate-config` now closes its `URLClassLoader` (releases jar handles on Windows).
- CI now asserts the benchmark detects exactly 33 findings, so a detection regression
  or new false positive fails the build.

## [0.12.0] - 2026-06-16

### Added
- **Autofix for SQL injection** — `scan --src <dir> --suggest-fixes` generates the
  parameterized-query fix (concatenation → `?` placeholders + bound parameters,
  surrounding quotes dropped) and shows it as a diff; `--fix` applies high-confidence
  fixes to the source (`--fix-confidence all` for every suggestion). The rewrite uses
  JavaParser and preserves formatting. Verified end-to-end: applying the fixes drops
  the benchmark's SQL findings from 15 to 1 (the remaining one is R2DBC, out of scope)
  and the patched code compiles.

## [0.11.0] - 2026-06-16

### Added
- **Near-miss sanitizer detection** (`scan --src <dir>`) — flags *attempted but
  incorrect* sanitization, the most dangerous class because the developer believes
  the flow is safe:
  - insufficient (`replaceAll("'", "")` before a SQL sink),
  - blacklist (`replace("<script>", "")` before an HTML sink),
  - discarded result (`htmlEscape(x)` ignored while the original is used),
  - wrong context (`htmlEscape` before `sendRedirect`) — a flow the taint engine
    alone treats as sanitized, so it would otherwise be a false negative.
  Shown in the console (`(near-miss sanitizer)`) and SARIF (`properties.nearMiss`).
- Benchmark grows to 37 cases (34 vulnerable, 3 safe): 33/33 by the taint engine,
  34 with the near-miss layer, 0 false positives.

## [0.10.0] - 2026-06-16

### Added
- **`@FeignClient` results as sources** — a value returned by a Feign client comes
  from a downstream service and is untrusted at the caller, catching cross-service
  injection. `String`-only, to stay precise.
- **`@Scheduled` methods as entry points** — scheduled jobs take no request input,
  but read external/persisted data internally; analysing their bodies lets those
  sources reach sinks.
- **`@Transactional` write-then-read** — input persisted and read back in one
  transaction is covered by the `@Repository`-read source model.

### Changed
- Benchmark grows to 33 cases (30 vulnerable, 3 safe); engine detects **30/30**
  with 0 false positives.

## [0.9.0] - 2026-06-16

### Added
- **Inline suppression** — silence a finding with a documented reason via a
  `// spring-taint: suppress <rule> - <reason>` comment; `scan --src <dir>` honours
  them and `spring-taint suppressions <dir>` lists them for audit. (Comment-based,
  since `@SuppressWarnings` is absent from bytecode.)
- **`validate-config` command** — resolves every method signature in a taint config
  against a classpath and reports the ones that do not exist, so a typo is caught
  instead of silently matching nothing.

## [0.8.0] - 2026-06-16

### Added
- **Confidence score** on every taint finding (0-100), derived from the call path
  (number of hops, sink category, lambdas on the path). Shown in the console and
  written to SARIF as `result.properties.confidence`; low scores are flagged
  "review manually".
- **Diff mode** — `scan --diff <ref>` reports only findings whose trace touches a
  file changed against `<ref>` (via `git diff`), for fast pull-request scans. A
  full scan is still recommended periodically, since matching is by file.

### Changed
- CLI and SARIF tool version strings updated.

## [0.7.0] - 2026-06-16

### Added
- **`config` command** — audits Spring config files (`application*.yml/.yaml/
  .properties`, `bootstrap*`) for insecure settings: hardcoded secrets, disabled
  TLS, Spring Security auto-configuration excluded, over-broad Actuator exposure,
  and the H2 console left enabled.
- **`misconfig` command** — a bytecode scan for insecure Spring patterns:
  `csrf().disable()` / `frameOptions().disable()`, `@CrossOrigin(origins = "*")`,
  `Cookie.setHttpOnly(false)` / `setSecure(false)`, and sensitive data
  (passwords, tokens, card numbers) passed to a logger.

## [0.6.0] - 2026-06-16

### Added
- **Five new vulnerability classes**, each benchmark-verified: JNDI injection
  (CWE-74), XXE (CWE-611), template injection / SSTI (CWE-1336), JPQL injection
  (CWE-89), and log injection (CWE-117).
- **New sources**: file upload (`MultipartFile.getOriginalFilename/getInputStream/
  getContentType`), `@MatrixVariable` and `@RequestPart`, request/session
  attributes, and Spring Batch `ItemReader`. Concrete-call sources from the config
  are now wired into the Tai-e analysis.
- **New sink**: open redirect via Spring MVC `ModelAndView.setViewName`.
- **Taint transfers** for transparent wrappers — `Optional` and
  `CompletableFuture` (`of`/`completedFuture` → wrapper, `get`/`orElse`/`join` →
  out). Transfers gain an optional `type` so an `Object` unwrap survives the cast
  the JVM inserts (`Optional<String>` → `String`).

### Changed
- Framework-internal sinks are filtered out (the logging facade, commons-logging,
  Reactor, Netty, …), so broad sinks like `Logger.info` report only application
  code — no false positives from a library logging the data it received.
- Benchmark grows to 30 cases (27 vulnerable, 3 safe); engine detects **27/27**
  with 0 false positives.

## [0.5.0] - 2026-06-16

### Added
- **Hardcoded-secrets scanner** — `spring-taint secrets <classes>`: a bytecode
  pattern scan (any JDK) for secret-named constants, known key formats (AWS,
  GitHub, Slack, PEM, …), and `@Value` defaults. Reported values are masked.
- **Web dashboard** (`dashboard/`, React + Vite + TypeScript) for exploring SARIF
  reports, including the full source→sink taint flow per finding.
- `--config` is now **merged** onto the built-in rules; `--no-default-config`
  restores replace behavior. The config gains a `transfers` section.

### Changed
- Relicensed to **MIT**. Added CONTRIBUTING, CODE_OF_CONDUCT, SECURITY, and
  GitHub issue/PR templates.

## [0.4.0] - 2026-06-16

### Added
- **Stored / second-order injection.** Data returned by a `@Repository` read method
  (returning `String`) is treated as untrusted, catching cross-request flows (e.g.
  stored XSS saved by one request and rendered by another). Conservative by design.
- A `transfers` section in the taint configuration (Tai-e taint transfers).

### Changed
- Benchmark grows to 20 cases (17 vulnerable, 3 safe); engine detects **17/17** with
  0 false positives.

## [0.3.0] - 2026-06-15

### Added
- Multi-framework sources: JAX-RS / Quarkus (`@QueryParam`, `@PathParam`, …) and
  Micronaut (`@QueryValue`, `@Body`, …), alongside Spring MVC/WebFlux and Kafka.
- Per-rule reference documentation (`docs/rules.md`).

## [0.2.0] - 2026-06-15

### Added
- Sources: `@PathVariable`, `@RequestBody`, `@RequestHeader`.
- Reactive WebFlux / R2DBC SQL injection via `DatabaseClient` (interface sink
  matched through call-site mode).
- A self-contained executable jar with the default config bundled.

## [0.1.0] - 2026-06-15

### Added
- Initial working release: interprocedural taint analysis for Spring Boot on Tai-e.
- Detects SQL injection (direct, cross-layer, via `@KafkaListener`), reflected and
  conditional-sanitizer XSS, SSRF, SpEL injection, path traversal, command injection,
  and open redirect.
- CLI with SARIF 2.1 output, a Docker-based GitHub Action, and a benchmark with
  documented ground truth.

[0.15.0]: https://github.com/GabrielBBaldez/spring-taint/releases/tag/v0.15.0
[0.14.0]: https://github.com/GabrielBBaldez/spring-taint/releases/tag/v0.14.0
[0.13.0]: https://github.com/GabrielBBaldez/spring-taint/releases/tag/v0.13.0
[0.12.1]: https://github.com/GabrielBBaldez/spring-taint/releases/tag/v0.12.1
[0.12.0]: https://github.com/GabrielBBaldez/spring-taint/releases/tag/v0.12.0
[0.11.0]: https://github.com/GabrielBBaldez/spring-taint/releases/tag/v0.11.0
[0.10.0]: https://github.com/GabrielBBaldez/spring-taint/releases/tag/v0.10.0
[0.9.0]: https://github.com/GabrielBBaldez/spring-taint/releases/tag/v0.9.0
[0.8.0]: https://github.com/GabrielBBaldez/spring-taint/releases/tag/v0.8.0
[0.7.0]: https://github.com/GabrielBBaldez/spring-taint/releases/tag/v0.7.0
[0.6.0]: https://github.com/GabrielBBaldez/spring-taint/releases/tag/v0.6.0
[0.5.0]: https://github.com/GabrielBBaldez/spring-taint/releases/tag/v0.5.0
[0.4.0]: https://github.com/GabrielBBaldez/spring-taint/releases/tag/v0.4.0
[0.3.0]: https://github.com/GabrielBBaldez/spring-taint/releases/tag/v0.3.0
[0.2.0]: https://github.com/GabrielBBaldez/spring-taint/releases/tag/v0.2.0
[0.1.0]: https://github.com/GabrielBBaldez/spring-taint/releases/tag/v0.1.0
