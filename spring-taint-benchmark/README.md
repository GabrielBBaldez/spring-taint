# Spring Taint Benchmark

Intentionally vulnerable — and intentionally safe — Spring Boot cases used as
ground truth for the analyzer, in the spirit of FlowDroid's DroidBench.

> ⚠️ This module contains deliberately insecure code. It exists only to exercise
> the analyzer. **Never deploy it.** (`maven.deploy.skip` is set.)

## How it works

- Every case is a small, **compilable** Spring component.
- The **source** and **sink** are marked with comments: `taint-source:` and `taint-sink:`.
- [`expected.yml`](expected.yml) is the machine-readable ground truth: each case is
  either `expected: true` (a real flow that must be reported) or `expected: false`
  (a safe flow that must **not** be reported).
- Positive cases measure **recall**; safe cases measure **precision**.

## Cases

| id | category | crosses layers | expected | detected |
|---|---|---|---|---|
| `sqli-direct` | SQL injection (CWE-89) | no (baseline) | vulnerable | ✅ |
| `sqli-through-service` | SQL injection (CWE-89) | yes — Controller→Service→Repository | vulnerable | ✅ |
| `sqli-three-layers` | SQL injection (CWE-89) | yes — +Validator (4 layers) | vulnerable | ✅ |
| `sqli-via-kafka` | SQL injection (CWE-89) | yes — `@KafkaListener` source | vulnerable | ✅ |
| `sqli-safe-parameterized` | SQL injection (CWE-89) | yes | **safe** (NamedParameter) | ✅ not flagged |
| `sqli-safe-prepared` | SQL injection (CWE-89) | no | **safe** (`?` parameter) | ✅ not flagged |
| `xss-reflected` | Reflected XSS (CWE-79) | no | vulnerable | ✅ |
| `xss-conditional-sanitizer` | XSS (CWE-79) | no | vulnerable (branch w/o escape) | ✅ |
| `xss-safe-escaped` | XSS (CWE-79) | no | **safe** (`HtmlUtils.htmlEscape`) | ✅ not flagged |
| `ssrf-rest-template` | SSRF (CWE-918) | no | vulnerable | ✅ |
| `spel-injection` | SpEL injection (CWE-917) | no | vulnerable | ✅ |
| `path-traversal-direct` | Path traversal (CWE-22) | no | vulnerable | ✅ |
| `cmdi-direct` | Command injection (CWE-78) | no | vulnerable | ✅ |
| `open-redirect` | Open redirect (CWE-601) | no | vulnerable | ✅ |
| `path-variable-sqli` | SQL injection (CWE-89) | no — `@PathVariable` source | vulnerable | ✅ |
| `request-body-sqli` | SQL injection (CWE-89) | no — `@RequestBody` source | vulnerable | ✅ |
| `request-header-xss` | XSS (CWE-79) | no — `@RequestHeader` source | vulnerable | ✅ |
| `webflux-sqli` | SQL injection (CWE-89) | reactive — R2DBC `DatabaseClient` | vulnerable | ✅ |
| `jaxrs-sqli` | SQL injection (CWE-89) | JAX-RS `@QueryParam` (Quarkus) | vulnerable | ✅ |
| `stored-xss` | XSS (CWE-79) | cross-request — `@Repository` read | vulnerable | ✅ |

**17 vulnerable, 3 safe.** Current engine result: **17/17 detected, 0 false positives.**
Sources covered: Spring (`@RequestParam`, `@PathVariable`, `@RequestBody`,
`@RequestHeader`), `@KafkaListener`, JAX-RS (`@QueryParam`), and `@Repository` reads
(stored / second-order injection). Sinks on interface library types (`sendRedirect`,
R2DBC `DatabaseClient.sql`) are matched via Tai-e `call-site-mode`.

> `secrets/HardcodedSecrets.java` is **not** a taint case — it feeds the separate
> `spring-taint secrets` scanner. Run: `spring-taint secrets spring-taint-benchmark/target/classes`.

## Layout

```
src/main/java/io/github/gabrielbbaldez/springtaint/benchmark/
├── sqli/
│   ├── direct/          # source and sink in one method (baseline)
│   ├── throughservice/  # Controller → Service → Repository (flagship)
│   ├── threelayers/     # Controller → Service → Validator → Repository
│   ├── viakafka/        # @KafkaListener payload as source
│   └── safe/            # parameterized queries (negative cases)
├── xss/
│   ├── reflected/       # request param → response writer
│   └── safe/            # HtmlUtils.htmlEscape (negative case)
├── conditional/         # sanitizer applied only on one branch
├── ssrf/
│   └── resttemplate/    # user URL → RestTemplate.getForObject
├── spel/                # user expression → ExpressionParser.parseExpression
├── openredirect/        # user URL → response.sendRedirect
├── sources/             # @PathVariable / @RequestBody / @RequestHeader sources
├── webflux/             # reactive R2DBC DatabaseClient (WebFlux)
├── jaxrs/               # JAX-RS @QueryParam source (Quarkus / Jakarta REST)
├── storedinjection/     # cross-request stored XSS via a @Repository read
├── pathtraversal/
│   └── direct/          # filename → new File(...)
└── cmdi/
    └── direct/          # host → Runtime.exec(...)
```

## Building

```bash
mvn -q -pl spring-taint-benchmark -am package
```

This produces the `.class` files under `target/classes` that the analyzer scans:

```bash
spring-taint scan spring-taint-benchmark/target/classes
```

## Adding a case

1. Create a compilable component under the matching category package.
2. Mark the source and sink with `taint-source:` / `taint-sink:` comments.
3. Add an entry to [`expected.yml`](expected.yml) and update the `summary` totals.
