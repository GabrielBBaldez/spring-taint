# Detection rules

Each rule is a vulnerability category: tainted data reaching a category's **sink**
without passing a **sanitizer**. Sources are framework entry points; sinks and
sanitizers are concrete library methods, configurable in
[`config/spring-taint.yml`](../config/spring-taint.yml).

## Sources (all rules)

External input is taint. Recognized entry points:

| Framework | Annotations |
|---|---|
| Spring MVC / WebFlux | `@RequestParam`, `@PathVariable`, `@RequestBody`, `@RequestHeader`, `@CookieValue`, `@ModelAttribute` |
| Spring Kafka | `@KafkaListener` (payload) |
| JAX-RS / Quarkus | `@QueryParam`, `@PathParam`, `@HeaderParam`, `@FormParam`, `@CookieParam` |
| Micronaut | `@QueryValue`, `@PathVariable`, `@Body`, `@Header` |
| Servlet | `HttpServletRequest.getParameter/getHeader/getQueryString` |
| Persistence | `@Repository` read methods returning `String` (`find*`/`get*`/`read*`/...) |

**Stored / second-order injection.** Data returned by a `@Repository` read method
is treated as untrusted, because an earlier request may have stored attacker input.
This catches cross-request flows (e.g. stored XSS: saved in one request, rendered in
another) that same-request analyzers miss. It is intentionally conservative — any
`@Repository` `String` read that reaches a sink is reported — so it trades some
precision for recall on second-order flows.

---

## `sql-injection` — CWE-89 (critical)

Untrusted data concatenated into SQL.

- **Sinks:** `JdbcTemplate.query/update/execute`, `java.sql.Statement.execute/executeQuery`, `EntityManager.createNativeQuery`, R2DBC `DatabaseClient.sql`
- **Sanitizers:** parameterized queries (`NamedParameterJdbcTemplate`, bound `?` parameters) — modelled as not-a-sink
- **Example:** `jdbc.query("… WHERE name = '" + name + "'", mapper)`

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

- **Sinks:** `HttpServletResponse.sendRedirect`
- **Example:** `response.sendRedirect(url)`

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

---

## Extending

Add your own sources, sinks, sanitizers and transfers in Tai-e's YAML format and
pass them with `--config`. Sinks declared on interface library types (no concrete
implementation on the classpath) are matched via Tai-e `call-site-mode`.

## Known limitations

- The reported trace is the shortest **call path** from source to sink (control
  flow); a value that detours through a side method may not appear as a hop.
  Exact data-flow traces require Tai-e to expose its taint flow graph.
- Reflection, dynamic proxies (Spring AOP/CGLib) and cross-request stored
  injection are not modelled.
- The analysis runs on **JDK 17** (Tai-e 0.5.1 does not read JDK 21 bytecode).
