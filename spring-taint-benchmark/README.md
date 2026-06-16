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
| `open-redirect` | Open redirect (CWE-601) | no | vulnerable | ⚠️ known gap |

**11 vulnerable, 3 safe.** Current engine result: **10/11 detected, 0 false positives.**
The single miss (`open-redirect`) is a documented gap: the sink (`sendRedirect`) is
called on an interface-typed parameter (`HttpServletResponse`), which has no
points-to object under the current entry-point modelling.

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
├── openredirect/        # user URL → response.sendRedirect (known gap)
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
