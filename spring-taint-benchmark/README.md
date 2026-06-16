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
| `sqli-via-rabbit` | SQL injection (CWE-89) | yes — `@RabbitListener` source (RabbitMQ) | vulnerable | ✅ |
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
| `map-param-sqli` | SQL injection (CWE-89) | no — `@RequestParam Map` via `Map.get` | vulnerable | ✅ |
| `bean-accessor-sqli` | SQL injection (CWE-89) | no — value round-trips through a DTO setter/getter | vulnerable | ✅ |
| `record-dto-sqli` | SQL injection (CWE-89) | no — `@RequestBody` record, taint via its accessor | vulnerable | ✅ |
| `builder-dto-sqli` | SQL injection (CWE-89) | no — Lombok-`@Builder`-shape DTO (`builder().term().build()` → getter) | vulnerable | ✅ |
| `fluent-dto-sqli` | SQL injection (CWE-89) | no — Lombok-`@Accessors(fluent)`-shape setter chains the taint | vulnerable | ✅ |
| `webflux-sqli` | SQL injection (CWE-89) | reactive — R2DBC `DatabaseClient` | vulnerable | ✅ |
| `jaxrs-sqli` | SQL injection (CWE-89) | JAX-RS `@QueryParam` (Quarkus) | vulnerable | ✅ |
| `stored-xss` | XSS (CWE-79) | cross-request — `@Repository` read | vulnerable | ✅ |
| `jndi-injection` | JNDI injection (CWE-74) | no — `InitialContext.lookup` (Log4Shell class) | vulnerable | ✅ |
| `xxe-document-builder` | XXE (CWE-611) | no — `DocumentBuilder.parse` | vulnerable | ✅ |
| `log-injection` | Log injection (CWE-117) | no — `Logger.info(String)` | vulnerable | ✅ |
| `template-injection-thymeleaf` | SSTI (CWE-1336) | no — Thymeleaf `process` | vulnerable | ✅ |
| `jpql-injection` | JPQL injection (CWE-89) | no — `EntityManager.createQuery` | vulnerable | ✅ |
| `open-redirect-modelandview` | Open redirect (CWE-601) | no — `ModelAndView.setViewName` | vulnerable | ✅ |
| `upload-filename-path-traversal` | Path traversal (CWE-22) | no — `MultipartFile.getOriginalFilename` source | vulnerable | ✅ |
| `matrix-variable-sqli` | SQL injection (CWE-89) | no — `@MatrixVariable` source | vulnerable | ✅ |
| `optional-transfer-sqli` | SQL injection (CWE-89) | through `Optional` (transfer) | vulnerable | ✅ |
| `completablefuture-transfer-sqli` | SQL injection (CWE-89) | through `CompletableFuture` (transfer) | vulnerable | ✅ |
| `feign-client-sqli` | SQL injection (CWE-89) | cross-service — `@FeignClient` result | vulnerable | ✅ |
| `scheduled-job-sqli` | SQL injection (CWE-89) | `@Scheduled` entry → `@Repository` read | vulnerable | ✅ |
| `transactional-stored-sqli` | SQL injection (CWE-89) | `@Transactional` write-then-read | vulnerable | ✅ |
| `nearmiss-sql-replace` | SQL injection (CWE-89) | near-miss — `replaceAll("'")` is not a sanitizer | vulnerable | ✅ |
| `nearmiss-xss-blacklist` | XSS (CWE-79) | near-miss — blacklisting `<script>` is bypassable | vulnerable | ✅ |
| `nearmiss-discarded-sanitizer` | XSS (CWE-79) | near-miss — `htmlEscape` result discarded | vulnerable | ✅ |
| `nearmiss-wrong-context` | Open redirect (CWE-601) | near-miss — `htmlEscape` before `sendRedirect` | vulnerable | ✅ with `--src` |

**40 vulnerable, 3 safe.** Current engine result: **39 of 40 detected by the taint engine
(0 false positives); the near-miss layer (`--src`) catches the remaining wrong-context
case (40).** The first three near-miss cases reach the sink anyway (the bad sanitizer
does not clear taint), so they are detected by default and annotated with the reason
under `--src`. Sources covered: Spring (`@RequestParam`, `@PathVariable`, `@RequestBody`,
`@RequestHeader`, `@MatrixVariable`, `MultipartFile`), `@KafkaListener`, `@RabbitListener`,
JAX-RS (`@QueryParam`), `@Repository` reads (stored / second-order injection),
`@FeignClient` results, and `@Scheduled` entry points. Sinks on interface library types
(`sendRedirect`, R2DBC `DatabaseClient.sql`, Thymeleaf `ITemplateEngine`,
`EntityManager`) are matched via Tai-e `call-site-mode`. Framework-internal sinks
(e.g. a logging facade logging the SQL it received) are filtered out, so broad sinks
like `Logger.info` do not produce false positives.

> Some files are **not** taint cases — they feed the separate pattern-based scanners:
> - `secrets/HardcodedSecrets.java` → `spring-taint secrets target/classes`
> - `misconfig/*` (insecure security config, permissive CORS, insecure cookies,
>   sensitive logging) → `spring-taint misconfig target/classes`
> - `resources/sample-config/application-insecure.yml` (and the safe counterpart)
>   → `spring-taint config spring-taint-benchmark/src/main/resources/sample-config`

## Layout

```
src/main/java/io/github/gabrielbbaldez/springtaint/benchmark/
├── sqli/
│   ├── direct/          # source and sink in one method (baseline)
│   ├── throughservice/  # Controller → Service → Repository (flagship)
│   ├── threelayers/     # Controller → Service → Validator → Repository
│   ├── viakafka/        # @KafkaListener payload as source
│   ├── viarabbit/       # @RabbitListener payload as source
│   └── safe/            # parameterized queries (negative cases)
├── xss/
│   ├── reflected/       # request param → response writer
│   └── safe/            # HtmlUtils.htmlEscape (negative case)
├── conditional/         # sanitizer applied only on one branch
├── ssrf/
│   └── resttemplate/    # user URL → RestTemplate.getForObject
├── spel/                # user expression → ExpressionParser.parseExpression
├── openredirect/        # user URL → response.sendRedirect / ModelAndView.setViewName
├── sources/             # @PathVariable / @RequestBody / @RequestHeader / @MatrixVariable
├── webflux/             # reactive R2DBC DatabaseClient (WebFlux)
├── jaxrs/               # JAX-RS @QueryParam source (Quarkus / Jakarta REST)
├── storedinjection/     # cross-request stored XSS via a @Repository read
├── upload/              # MultipartFile.getOriginalFilename → new File(...)
├── feign/               # @FeignClient result (downstream service) → SQL
├── scheduled/           # @Scheduled job → @Repository read → SQL
├── transactional/       # @Transactional write-then-read → SQL
├── nearmiss/            # attempted-but-wrong sanitization (replace, discarded, wrong context)
├── jndi/                # user name → InitialContext.lookup
├── xxe/                 # user URI → DocumentBuilder.parse
├── loginjection/        # user input → Logger.info(String)
├── templateinjection/   # user template name → Thymeleaf ITemplateEngine.process
├── jpql/                # user input → EntityManager.createQuery
├── transfers/           # taint through Optional / CompletableFuture wrappers
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
