# Spring Taint Analyzer

> Interprocedural taint analysis for Spring Boot applications, built on [Tai-e](https://github.com/pascal-lab/Tai-e).
> Detects data-flow vulnerabilities that conventional tools such as SonarQube cannot reach.

> 🚧 **Early development.** The benchmark and project structure are in place; the analysis engine is being wired to Tai-e. See [Status](#status).

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

The benchmark has **14 cases (11 vulnerable, 3 safe)** across SQL injection
(direct, through-service, four-layer, via-Kafka), reflected & conditional-sanitizer
XSS, SSRF, SpEL injection, path traversal, command injection, and open redirect,
with documented ground truth in [`expected.yml`](spring-taint-benchmark/expected.yml).

Current engine result: **10/11 vulnerable cases detected, 0 false positives** on
the 3 safe cases. The one miss (`open-redirect`) is a documented gap — its sink is
called on an interface-typed parameter that has no points-to object yet. Full
table and per-case status: [benchmark README](spring-taint-benchmark/README.md).

Positive cases measure **recall**; safe cases measure **precision**.

---

## Scope by phases

- **Phase 1 — Spring MVC (MVP):** SQL injection, XSS, path traversal, command injection, SSRF, SpEL injection, open redirect. Sources: `@RequestParam`, `@PathVariable`, `@RequestBody`, `@RequestHeader`, `@CookieValue`, `@ModelAttribute`, servlet API. Exit criterion: detect every benchmark case with zero false negatives and precision > 80%.
- **Phase 2 — gaps left open by existing OSS tools:** `@KafkaListener` as a source, conditional sanitizers, custom method sanitizers, cross-request stored injection, WebFlux / async (`Mono`/`Flux` as transparent taint wrappers).
- **Phase 3 — roadmap (separate repos):** Quarkus / JAX-RS, Micronaut, gRPC, RabbitMQ.

The full technical scope lives in [`docs/design/spring-taint-scope.md`](docs/design/spring-taint-scope.md).

---

## Usage (planned)

```bash
# Basic scan
spring-taint scan ./my-project

# Custom configuration
spring-taint scan --config spring-taint.yml ./my-project

# SARIF output (GitHub Advanced Security, GitLab SAST, VS Code)
spring-taint scan --output results.sarif ./my-project

# Filter by severity, show full trace
spring-taint scan --severity critical,high --verbose ./my-project
```

Expected output:

```
[CRITICAL] sql-injection @ GET /users/search
  Source:  UserController.java:12 — @RequestParam String name
  Flow:    UserController → UserService.search() → UserRepository.findByName()
  Sink:    UserRepository.java:34 — JdbcTemplate.query(sql)
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

Pass the target's dependency classpath with `--libs` so types like `JdbcTemplate`
resolve:

```bash
spring-taint scan <classes> --libs <dependency-classpath> --config config/spring-taint.yml
```

> **The analysis currently runs on JDK 17.** Tai-e 0.5.1's frontend cannot read
> JDK 21 bytecode, so run the analyzer with a JDK 17 runtime (the project still
> compiles to Java 17 on any JDK 17+).

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
- [x] precision/recall on the current benchmark — **10/11 vulnerable cases detected, 0 false positives** across SQL injection (direct / through-service / four-layer / via-Kafka), reflected & conditional XSS, SSRF, SpEL, path traversal, command injection; open redirect is a documented gap
- [ ] GitHub Action
- [ ] Public release v0.1.0

---

## Known limitations

Static analysis has inherent limits. For this project:

- **Java reflection** (`Class.forName()`, `Method.invoke()`) can break the flow
- **Spring dynamic proxies** (AOP / CGLib) introduce indirection that may break the call graph
- **Data from the database** — stored injection requires modelling persistence as a taint propagator
- **Complex lambdas / method references** — partial coverage via Tai-e
- **Cross-service flows** over HTTP are not tracked in Phase 1

Each release documents its limitations explicitly, alongside the test cases that exercise them.

---

## License

[Apache License 2.0](LICENSE).
