<p align="center">
  <img src="docs/assets/logo.svg" alt="Spring Taint Analyzer" width="104" height="104" />
</p>

# Spring Taint Analyzer

[![CI](https://github.com/GabrielBBaldez/spring-taint/actions/workflows/ci.yml/badge.svg)](https://github.com/GabrielBBaldez/spring-taint/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/GabrielBBaldez/spring-taint?sort=semver)](https://github.com/GabrielBBaldez/spring-taint/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Java](https://img.shields.io/badge/Java-17%2B-orange.svg)](#building)

> Interprocedural taint analysis for Spring Boot applications, built on [Tai-e](https://github.com/pascal-lab/Tai-e).
> Detects multi-layer data-flow vulnerabilities that conventional tools such as SonarQube cannot reach.

Detects **12 vulnerability classes** across **6 frameworks**, including cross-layer,
reactive, cross-service, and cross-request stored injection — **33/33 vulnerable
benchmark cases with 0 false positives**, plus a near-miss layer that flags
*attempted-but-incorrect* sanitization. Ships as a CLI, a self-contained jar, a
Docker image, and a GitHub Action with SARIF 2.1 output.

---

## The problem

Consider this seemingly harmless Spring Boot code:

```java
// Controller
@GetMapping("/users")
public List<User> search(@RequestParam String name) {
    return userService.search(name);
}

// Service
public List<User> search(String name) {
    String filtered = nameFilter(name); // looks like sanitization, but isn't
    return userRepo.findByName(filtered);
}

// Repository
public List<User> findByName(String name) {
    return jdbc.query(
        "SELECT * FROM users WHERE name = '" + name + "'", // 🚨 SQL Injection
        mapper
    );
}
```

The value comes from `@RequestParam`, crosses the service and repository layers, and reaches a SQL query without sanitization. A trivial payload like `name = ' OR '1'='1` exposes the whole table.

**SonarQube does not detect this path.** It only flags the case where the sink is in the same method as the source. The real vulnerability lives in flows that cross multiple layers — and that is exactly where this project operates.

---

## What is taint analysis

Taint analysis tracks the flow of untrusted data through a system using three concepts:

```
[SOURCE] ──► data flow ──► [SANITIZER?] ──► [SINK]
                                │
                        if absent → alert
```

- **Source** — where external data enters: `@RequestParam`, `@RequestBody`, `@KafkaListener`
- **Sanitizer** — what cleans the data: `HtmlUtils.htmlEscape()`, parameterized queries, `@Valid`
- **Sink** — where dangerous data is consumed: `JdbcTemplate.execute()`, `Runtime.exec()`, `response.write()`

If data flows from a source to a sink **without passing through a sanitizer** → potential vulnerability.

The analysis is **interprocedural**: it tracks data across methods, classes, and abstraction layers — not just within a single function.

---

## Positioning: complementary to SonarQube

This project does **not** replace SonarQube. They serve different purposes:

| Tool | Purpose | Interprocedural taint |
|---|---|---|
| SonarQube | General quality + bugs + simple vulnerabilities | ❌ |
| Semgrep OSS | Static code patterns | ❌ |
| Semgrep Pro | Interprocedural taint | ✅ — but **paid** |
| Checkmarx / Veracode | Full enterprise SAST | ✅ — but **expensive** |
| **Spring Taint Analyzer** | Interprocedural taint for Spring Boot | ✅ — **free** |

Where it differs in practice — the Spring-specific capabilities that depend on real
interprocedural taint:

| Capability | Spring Taint | SonarQube (free) | Semgrep OSS |
|---|:---:|:---:|:---:|
| Interprocedural taint (across methods/layers) | ✅ | ❌ | ❌ |
| `@KafkaListener` / `@FeignClient` as sources | ✅ | ❌ | ❌ |
| `MultipartFile` / `@MatrixVariable` as sources | ✅ | ❌ | ❌ |
| Conditional sanitizers | ✅ | ❌ | ❌ |
| Cross-request stored injection | ✅ | ❌ | ❌ |
| WebFlux / Reactor (`Mono` / `Flux`) | ✅ | ❌ | ❌ |
| JPQL / template / JNDI / XXE injection | ✅ | ❌ | ❌ |
| Spring Security & `application.yml` misconfig | ✅ | ❌ | ❌ |
| Near-miss sanitizer detection (wrong/insufficient sanitization) | ✅ | ❌ | ❌ |
| Autofix — applies the fix (parameterized query / output escaping) | ✅ | ❌ | ❌ |
| Per-finding confidence score | ✅ | ❌ | ❌ |
| Diff mode + baseline for pull requests | ✅ | ❌ | partial |
| SARIF 2.1 output | ✅ | ✅ | ✅ |
| Free / open source | ✅ | ✅ | ✅ |

> **Semgrep Pro** has interprocedural taint but is a paid product (~$35/dev/month).
> Spring Taint Analyzer delivers the Spring Boot–focused equivalent, free.

Expected use in a CI pipeline:

```yaml
- sonarqube scan     # general quality, code smells, coverage
- spring-taint scan  # deep data-flow vulnerabilities
```

**Value proposition in one sentence:** you already use SonarQube — this project detects what it cannot see.

---

## Architecture

Built on **[Tai-e](https://github.com/pascal-lab/Tai-e)** (Nanjing University, ISSTA 2023), a modern static-analysis framework for Java. Tai-e solves the hard parts — call-graph construction, context-sensitive pointer analysis, and interprocedural **IFDS** taint propagation. Our work is the Spring layer on top of it.

```
Spring Boot project
       │  compile (Maven / Gradle)
       ▼
Bytecode (.class / JAR)            ← analysis runs here, not on source
       │
       ▼
Tai-e: Call Graph + Pointer Analysis
       │
       ▼
IFDS Taint Propagation
       │
       ▼
Spring Source/Sink Config          ← our differentiator
(@RequestParam, @KafkaListener,
 JdbcTemplate, Runtime.exec…)
       │
       ▼
SARIF 2.1 report
(terminal / GitHub / GitLab / VS Code)
```

Operating on bytecode (not source) gives precise inheritance/generics resolution, analysis of third-party dependencies without source, and independence from any IDE or build system.

---

## Project layout

```
spring-taint/
├── config/
│   └── spring-taint.yml          # default Spring sources/sinks/sanitizers (Tai-e format)
├── docs/
│   └── design/                   # technical scope & design notes
├── spring-taint-engine/          # analyzer: CLI, config loader, Tai-e adapter, SARIF reporter
└── spring-taint-benchmark/       # intentionally vulnerable Spring Boot cases + ground truth
```

---

## Benchmark

Like FlowDroid's DroidBench, this repo ships a benchmark of intentionally vulnerable (and intentionally safe) Spring Boot cases. Every advertised detection is validated against it before release.

The benchmark has **40 cases (37 vulnerable, 3 safe)** across SQL and JPQL injection
(direct, through-service, four-layer, via Kafka and RabbitMQ, reactive R2DBC), reflected,
conditional-sanitizer and **cross-request stored** XSS, SSRF, SpEL, JNDI, XXE,
template injection (SSTI), log injection, path traversal, command injection, and
open redirect — with sources from Spring (`@RequestParam`, `@PathVariable`,
`@RequestBody`, `@RequestHeader`, `@MatrixVariable`, `MultipartFile`),
`@KafkaListener`, `@RabbitListener`, JAX-RS (`@QueryParam`), `@Repository` reads,
**`@FeignClient` results, `@Scheduled` jobs and `@Transactional` write-then-read**,
plus taint flowing through `Optional` / `CompletableFuture` wrappers. Ground truth is
in [`expected.yml`](spring-taint-benchmark/expected.yml).

Current engine result: **36 of 37 vulnerable cases detected by the taint engine alone,
0 false positives** on the 3 safe cases; the near-miss layer (`--src`) catches the
remaining wrong-context flow (37) and explains the rest. Full table: [benchmark README](spring-taint-benchmark/README.md).
Per-rule reference: [docs/rules.md](docs/rules.md).

Positive cases measure **recall**; safe cases measure **precision**.

Beyond the synthetic benchmark, the analyzer is run against real OSS apps, across both
Spring Boot 3 (`jakarta`) and Spring Boot 2 (`javax`):

- **spring-petclinic** (clean, Boot 4.0) — engaged correctly (9 entry points, 12
  sources) and reported **0 false positives**, plus one legitimate config finding the
  project itself flags as production-unsafe.
- **spring-petclinic-rest** (clean, larger — ~126 classes, real `JdbcTemplate` usage)
  — **0 false positives** at scale (31 entry points, 46 sources; analysis ~0.2s).
- **sql-injection-web** (vulnerable) — found the **cross-layer** SQL injection
  (controller → repository, two files) at 99% confidence and generated the fix.
- **Contrast vulnerable-spring-boot-application** (vulnerable, Boot 2 / `javax`, value
  via a `@RequestParam Map`) — found the cross-layer SQL injection at 99%.

See [docs/validation.md](docs/validation.md).

---

## Real CVEs of the classes it detects

The benchmark proves recall on synthetic cases; these are **public CVEs of the same
bug classes** in the wild. The analyzer reasons over application bytecode and reports
the interprocedural source-to-sink form of each flow — so it catches these patterns
when the vulnerable call lives in the analyzed code, not only inside a third-party
library.

| Class | Detector | Representative public CVE | The data flow |
|---|---|---|---|
| SQL injection (CWE-89) | `sql-injection` | [CVE-2020-5427 / CVE-2020-5428](https://spring.io/security/cve-2020-5428/) — Spring Cloud Data Flow / Task | a request-controlled `sort` column is concatenated into the task-execution query |
| SQL injection (CWE-89) | `sql-injection` | [CVE-2016-6652](https://spring.io/security/cve-2016-6652/) — Spring Data JPA | a `Sort` value from the request reaches the generated SQL (blind SQLi) |
| SQL injection (CWE-89) | `sql-injection` | [CVE-2024-54762](https://nvd.nist.gov/vuln/detail/CVE-2024-54762) — RuoYi (Spring Boot admin) | an authenticated request parameter reaches a query without sanitization |
| SpEL injection (CWE-917) | `spel-injection` | [CVE-2018-1273](https://nvd.nist.gov/vuln/detail/CVE-2018-1273) — Spring Data Commons | a crafted request payload property path is evaluated as a SpEL expression |

Each is a request value flowing across methods into a sink with no sanitizer in
between — exactly the shape this tool tracks. (For a CVE whose vulnerable call sits in
a framework rather than the app, the analyzer reports it only when that call is reached
from the analyzed code.)

---

## Scope by phases

- **Phase 1 — Spring MVC (MVP):** SQL injection, XSS, path traversal, command injection, SSRF, SpEL injection, open redirect. Sources: `@RequestParam`, `@PathVariable`, `@RequestBody`, `@RequestHeader`, `@CookieValue`, `@ModelAttribute`, servlet API. Exit criterion: detect every benchmark case with zero false negatives and precision > 80%.
- **Phase 2 — gaps left open by existing OSS tools (done):** `@KafkaListener` and `@RabbitListener` as sources, conditional sanitizers, custom method sanitizers, cross-request stored injection, WebFlux / async (`Mono`/`Flux` as transparent taint wrappers).
- **Phase 3 — multi-framework & robustness (done):** JAX-RS / Quarkus and Micronaut sources; JNDI / XXE / template / JPQL / log-injection sinks; `@FeignClient`, `@Scheduled` and `@Transactional` sources; configuration and misconfiguration audits.
- **Phase 4 — roadmap:** gRPC sources, an IntelliJ plugin, and publishing the image to GHCR.

The full technical scope lives in [`docs/design/spring-taint-scope.md`](docs/design/spring-taint-scope.md).

---

## Usage

The commands (the runnable `java -jar …/spring-taint-all.jar` form is in
[Building](#building); `scan` needs the target's dependency classpath via `--libs`):

```bash
# Basic scan
spring-taint scan target/classes --libs "<dependency classpath>"

# Custom configuration (merged onto the built-in rules)
spring-taint scan target/classes --libs "…" --config spring-taint.yml

# SARIF output (GitHub Advanced Security, GitLab SAST, VS Code)
spring-taint scan target/classes --libs "…" --output results.sarif

# Filter by severity, show the full trace
spring-taint scan target/classes --libs "…" --severity critical,high --verbose

# Only findings touching files changed vs a base ref (fast PR scans)
spring-taint scan target/classes --libs "…" --diff origin/main

# Near-miss notes + suggested parameterized-query fixes (needs the sources)
spring-taint scan target/classes --libs "…" --src src/main/java --suggest-fixes

# Apply the high-confidence fixes to the source
spring-taint scan target/classes --libs "…" --src src/main/java --fix

# Adopt on a legacy codebase: record today's findings, then fail only on NEW ones
spring-taint scan target/classes --libs "…" --baseline spring-taint-baseline.txt
```

Example output (every taint finding carries a confidence score):

```
[CRITICAL] sql-injection (confidence: 95%)
  Source:  UserController.java:28 - search() - tainted parameter
  Flow:    UserController.search() -> UserService.search() -> UserRepository.query()
  Sink:    UserRepository.java:27 - sink: query()
  Sanitizer: none detected
```

---

## Extensibility

Teams can add their own rules in Tai-e's YAML format:

```yaml
sources:
  - { kind: call,  method: "<com.myapp.LegacyInput: java.lang.String readUserData()>", index: result }
  - { kind: param, method: "<com.myapp.EventHandler: void onEvent(java.lang.String)>", index: 0 }

sinks:
  - { method: "<com.myapp.LegacyDao: void rawExecute(java.lang.String)>", index: 0 }

sanitizers:
  - { method: "<com.myapp.Validator: java.lang.String sanitize(java.lang.String)>", index: 0 }
```

---

## Building

Requires JDK 17+ and Maven.

```bash
mvn -q clean package          # build engine + benchmark
mvn -q -pl spring-taint-benchmark package   # compile the benchmark cases only
```

### Running a scan

Build the self-contained jar and scan compiled classes. Pass the target's
dependency classpath with `--libs` so framework types like `JdbcTemplate` resolve
(the taint config is bundled, so `--config` is optional):

```bash
java -jar spring-taint-engine/target/spring-taint-all.jar \
  scan target/classes --libs "$(... your dependency classpath ...)" \
  --output results.sarif
```

> **The analysis currently runs on JDK 17.** Tai-e 0.5.1's frontend cannot read
> JDK 21 bytecode, so run the analyzer with a JDK 17 runtime (the project still
> compiles to Java 17 on any JDK 17+).

A custom `--config` is **merged** onto the built-in rules (use `--no-default-config`
to replace them instead).

### Secrets, configuration and misconfiguration scans

Three pattern-based scans (any JDK, no taint engine) complement the taint analysis:

```bash
# Hardcoded secrets in bytecode — secret-named constants, known key formats
# (AWS, GitHub, …), and @Value defaults
java -jar …/spring-taint-all.jar secrets target/classes

# Insecure settings in application*.yml / .properties — hardcoded secrets,
# disabled TLS, Security auto-config excluded, Actuator "*", H2 console
java -jar …/spring-taint-all.jar config src/main/resources

# Insecure Spring code in bytecode — csrf()/frameOptions().disable(),
# @CrossOrigin("*"), insecure cookies, sensitive data logged
java -jar …/spring-taint-all.jar misconfig target/classes
```

---

## GitHub Action

Run the analyzer in CI and upload findings to GitHub code scanning. The action
runs as a Docker container on JDK 17; give it the compiled classes and the
dependency classpath:

```yaml
- uses: actions/checkout@v4
- uses: actions/setup-java@v4
  with: { distribution: temurin, java-version: '17' }

- run: mvn -B -ntp package -DskipTests
- id: cp
  run: echo "value=$(mvn -q dependency:build-classpath -Dmdep.outputFilterFile=/dev/stdout)" >> "$GITHUB_OUTPUT"

- name: Spring Taint Analysis
  uses: GabrielBBaldez/spring-taint@main
  with:
    path: target/classes
    libs: ${{ steps.cp.outputs.value }}
    output: results.sarif
    severity: critical,high

- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: results.sarif
```

See [`action.yml`](action.yml) for all inputs. This repo also scans its own
benchmark on every push — see [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

### Pull-request review

[`examples/pr-security.yml`](examples/pr-security.yml) is a copy-paste workflow for
your own project: on every PR it scans only the changed code (`--diff`), uploads
SARIF so findings appear **inline in the PR** (GitHub code scanning), and posts the
**suggested fixes** (parameterized queries / output escaping) as a PR comment. Pair
it with `--baseline` to gate only on newly introduced issues.

---

## Dashboard

A web console (React + Vite + TypeScript) visualizes the SARIF output: severity
breakdown, findings by rule, and the full **source → sink taint flow** for each
finding. Drop a `.sarif` file to load your own report. See
[`dashboard/`](dashboard/).

```bash
cd dashboard && npm install && npm run dev   # → http://localhost:4321
```

---

## Status

- [x] Scope and positioning
- [x] Engine choice (Tai-e)
- [x] Gap mapping vs. competitors
- [x] Project scaffold (Maven multi-module, CLI skeleton, config loader, SARIF model)
- [x] Initial benchmark: SQL injection (direct / through-service / via-Kafka / safe), reflected XSS, path traversal, command injection
- [x] Engine: Tai-e IFDS wired end-to-end on the benchmark
- [x] Spring source layer: annotation → Tai-e param-source generation
- [x] Functional CLI with SARIF output
- [x] precision/recall on the current benchmark — **30/30 vulnerable cases detected, 0 false positives** across SQL / JPQL injection (direct / through-service / four-layer / via-Kafka / reactive R2DBC), reflected / conditional / **cross-request stored** XSS, SSRF, SpEL, JNDI, XXE, template injection (SSTI), log injection, path traversal, command injection, open redirect; multi-framework sources (Spring MVC/WebFlux, Kafka, JAX-RS/Quarkus, Micronaut, `@Repository` reads, `@FeignClient`, `@Scheduled`)
- [x] Phase 2 differentiators: `@KafkaListener` source, conditional sanitizers, stored / second-order injection
- [x] GitHub Action (Docker) + self-contained jar + CI workflow
- [x] Web dashboard (React + Vite) for SARIF reports
- [x] Hardcoded-secrets scanner (`secrets` command); mergeable `--config`
- [x] Robustness pass: JNDI / XXE / log / template / JPQL sinks, file-upload and `@MatrixVariable` sources, `Optional` / `CompletableFuture` taint transfers, framework-internal sink filtering
- [x] Configuration & misconfiguration audits: `config` (insecure `application.yml`/`.properties`) and `misconfig` (CSRF/clickjacking disabled, CORS `*`, insecure cookies, sensitive data logged)
- [x] Adoption: per-finding confidence score (console + SARIF), `scan --diff <ref>` for fast pull-request scans, inline `// spring-taint: suppress` comments (`--src` / `suppressions`), and `validate-config` to catch typo'd custom rules
- [x] Advanced sources: `@FeignClient` results (cross-service), `@Scheduled` jobs as entry points, and `@Transactional` write-then-read stored injection
- [x] Near-miss sanitizers (`--src`): flags insufficient (quote-stripping), blacklist, discarded-result, and wrong-context sanitization — the "I'm sure this is safe" class of bug
- [x] Autofix (`--suggest-fixes` / `--fix`): rewrites a concatenated SQL query into a parameterized one; verified end-to-end (applying the fixes drops the benchmark's SQL findings 15 → 1 and the patched code compiles)
- [x] Unit-test suite for the scanners (18 tests, with regression coverage); the bytecode scanners (`secrets`/`misconfig`) read any-JDK class files (ASM 9.7)
- [x] Autofix covers XSS (wrap in `HtmlUtils.htmlEscape`) as well as SQL; baseline mode (`--baseline`) to adopt on a legacy codebase and gate CI on new findings only

---

## Known limitations

Static analysis has inherent limits. For this project:

- **Java reflection** (`Class.forName()`, `Method.invoke()`) can break the flow
- **Spring dynamic proxies** (AOP / CGLib) introduce indirection that may break the call graph
- **Entity / DTO field tracking** — sources are `String`-only (a `@Repository`/`@FeignClient` returning a DTO whose getter is later read is not followed), a deliberate precision-over-recall choice
- **Complex lambdas / method references** — partial coverage via Tai-e
- **The taint analysis runs on JDK 17** — Tai-e 0.5.1 cannot read JDK 21 bytecode

Each release documents its limitations explicitly, alongside the test cases that exercise them.

---

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for the dev
setup, how to add a benchmark case, and the PR checklist. Please also read the
[Code of Conduct](CODE_OF_CONDUCT.md). To report a security issue, see
[SECURITY.md](SECURITY.md).

## Acknowledgements

Built on [Tai-e](https://github.com/pascal-lab/Tai-e) (Nanjing University), which
provides the call-graph construction, pointer analysis, and IFDS taint propagation.
Tai-e is licensed under LGPL-3.0; this project depends on it as a library.

## License

[MIT](LICENSE) © Gabriel Baldez.
