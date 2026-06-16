# Real-world validation

Beyond the synthetic [benchmark](../spring-taint-benchmark/README.md) (which measures
recall and precision against known ground truth), the analyzer is run against real
open-source Spring Boot applications: a clean app to measure **precision** (false
positives on code not written for it) and intentionally-vulnerable apps to measure
**recall** (does it find a real, cross-layer flaw) — across both Spring Boot 3
(`jakarta`) and Spring Boot 2 (`javax`).

## spring-petclinic

[`spring-projects/spring-petclinic`](https://github.com/spring-projects/spring-petclinic)
— the canonical Spring Boot sample. A clean, idiomatic application, so it is a precision
test: a good tool should report **no false positives** on it.

- Build: `mvn clean compile` on JDK 17 — Spring Boot 4.0.3 / Spring Framework 7.0.5,
  30 application classes.
- Commands: `scan` (taint), `secrets`, `misconfig` on the compiled classes; `config` on
  `src/main/resources`.

| Scan | Result | Assessment |
|---|---|---|
| Taint (`scan`) | **0 findings** | The Spring layer engaged correctly — it registered **9 entry points** and **12 parameter sources** from petclinic's controllers — and found no flows, because petclinic uses parameterized Spring Data JPA, not string-built SQL. **0 false positives.** |
| `secrets` | 0 findings | No hardcoded secrets. Correct. |
| `misconfig` | 0 findings | No `csrf().disable()`, permissive CORS, insecure cookies, or sensitive logging. Correct. |
| `config` | **1 finding** (actuator-exposure, `application.properties:21`) | **True positive:** `management.endpoints.web.exposure.include=*`. Petclinic's own comment on the line reads *"Don't do this in production, only for development and testing."* |

**Outcome: zero false positives across all four scans on a modern, real-world Spring
Boot application, and one legitimate configuration finding** that the project itself
documents as production-unsafe. The engine correctly identified petclinic's controllers
as entry points despite it targeting a much newer Spring version than the benchmark.

## spring-petclinic-rest (precision at scale)

[`spring-petclinic/spring-petclinic-rest`](https://github.com/spring-petclinic/spring-petclinic-rest)
— a larger, clean REST application (~126 compiled classes, mixing Spring Data JPA and
hand-written `JdbcTemplate` repositories). Built on JDK 17.

- The Spring layer scaled up correctly: **31 entry points** and **46 parameter
  sources** registered.
- **0 findings, 0 false positives.** Pointer analysis ran in ~0.2s, so performance is
  not a problem at this size.

This confirms the petclinic precision result is not a small-app artifact: on a
126-class app with real `JdbcTemplate` usage, the parameterized queries are correctly
*not* flagged.

## sql-injection-web (recall)

[`littlewhywhat/sql-injection-web`](https://github.com/littlewhywhat/sql-injection-web)
— a small, intentionally-vulnerable Spring Boot app (not written for this tool). The
flaw crosses a layer boundary: a request parameter in the controller reaches a
JdbcTemplate call in a separate repository class.

```java
// ProductController.java
@RequestMapping(value = "/add", method = RequestMethod.GET)
public @ResponseBody boolean addProduct(@RequestParam("name") String name) {
    return products.add(id, name);                 // crosses into the repository
}

// ProductRepository.java
public boolean add(long id, String name) {
    jdbcTemplate.execute("INSERT INTO products(id,name) values(" + id + ", '" + name + "')");
}
```

Result — **detected**, with the correct fix generated:

```
[CRITICAL] sql-injection (confidence: 99%)
  Source:  ProductController.java:33 - addProduct() - tainted parameter
  Sink:    ProductRepository.java:45 - execute()

[suggested fix] sql-injection - ProductRepository.java:45
  - "values(" + id + ", '" + name + "')");
  + jdbcTemplate.update("INSERT INTO products(id,name) values(?, ?)", id, name);
```

The flow is **interprocedural across two files** — precisely the case a same-method
analyzer (e.g. SonarQube Community) does not report. (The repo's original 2014 build
was replaced with a modern Spring Boot 3 / JDK 17 `pom.xml`; the vulnerable source is
unchanged.)

## vulnerable-spring-boot-application (recall, Spring Boot 2 / javax)

[`Contrast-Security-OSS/vulnerable-spring-boot-application`](https://github.com/Contrast-Security-OSS/vulnerable-spring-boot-application)
— a vendor-maintained vulnerable app on **Spring Boot 2** (`javax.*`), with a SQL
injection that also exercises two patterns the synthetic benchmark did not:

```java
// ProviderController.java — the request binds ALL params into a Map
public String search(@RequestParam Map<String, String> body, Model model) {
    providerSearchDAO.getProvidersInZipCode(body.get("zipCode"));   // value via Map.get
}
// ProviderSearchDAO.java
String q = "select * from PROVIDERS where ... zip_code = '" + zipCode + "'";
em.createNativeQuery(q);                                            // javax.persistence
```

Result — **detected**:

```
[CRITICAL] sql-injection (confidence: 99%)
  Source:  ProviderController.java:32 - search() - tainted parameter
  Sink:    ProviderSearchDAO.java:18 - createNativeQuery()
```

This run surfaced (and then drove fixes for) two real-world gaps: the sink is
`javax.persistence` (Spring Boot 2 / Java EE, still widely deployed), and the value
is read from a `@RequestParam Map` via `Map.get`. Support for `javax.*` library
signatures and a `Map.get` taint transfer were added so the flow is caught. (Built
with a Spring Boot 2.7 / JDK 17 `pom.xml`; the vulnerable source is unchanged.)

### Reproduce

```bash
git clone --depth 1 https://github.com/spring-projects/spring-petclinic.git
cd spring-petclinic && mvn -q clean compile -DskipTests          # build on JDK 17
mvn -q dependency:build-classpath -Dmdep.outputFile=cp.txt

# from this repo (run the analysis on a JDK 17 runtime):
java -jar spring-taint-all.jar scan target/classes --libs "$(cat cp.txt)"
java -jar spring-taint-all.jar secrets  target/classes
java -jar spring-taint-all.jar misconfig target/classes
java -jar spring-taint-all.jar config   src/main/resources
```

## demo-app (true positives and false positives, side by side)

The real apps above each isolate one property — petclinic measures precision, the
vulnerable apps measure recall. [`examples/demo-app`](../examples/demo-app) puts both
in one run, and covers the two categories the real-app set did not have a clean target
for: **reflected XSS** and **command injection**, plus a **cross-layer SQL injection**.

Each category ships a vulnerable endpoint and a safe sibling, so the same scan proves a
true positive *and* a false-positive check at once:

| Category | Vulnerable (should flag) | Safe (must not flag) | Why safe |
|---|---|---|---|
| XSS | `/greet` | `/greet-safe` | `HtmlUtils.htmlEscape` before the writer |
| Command injection | `/ping` | `/uptime` | constant command, no request data |
| SQL injection | `/accounts` -> `AccountService` | `/accounts-safe` | bound `?` parameter, not concatenation |

Result — exactly three findings, one per vulnerable endpoint, nothing on the siblings:

```
[CRITICAL] command-injection (confidence: 99%)
  Source:  OpsController.java:16 - source: ping() - tainted parameter
  Sink:    OpsController.java:16 - sink: exec()
[CRITICAL] sql-injection (confidence: 99%)
  Source:  AccountController.java:21 - source: delete() - tainted parameter
  Sink:    AccountService.java:18 - sink: update()
[HIGH] xss (confidence: 90%)
  Source:  GreetingController.java:18 - source: greet() - tainted parameter
  Sink:    GreetingController.java:18 - sink: write()
3 finding(s).
```

The `sql-injection` flow crosses from `AccountController` into `AccountService`, so it
also exercises the interprocedural path. Build and scan instructions are in the demo
app's [README](../examples/demo-app/README.md).

## Limitations surfaced by real-world testing

Running on real apps also exposes where the engine stops — recorded honestly:

- **Framework callbacks.** In `kaakaww/javaspringvulny`, the SQL injection flows
  through a DTO getter (`search.getSearchText()`) read inside a Hibernate
  `session.doReturningWork(...)` anonymous callback. Bean getters/setters are now
  modelled as taint containers (v0.16.0), so the getter half is covered; the
  remaining gap is taint into framework-supplied callbacks (the `Connection` handed to
  `doReturningWork`). Modelling common callback interfaces is future work.
- **Build/runtime constraint.** The taint `scan` needs the target compiled to JDK ≤17
  bytecode (Tai-e frontend limitation); the pattern scanners (`secrets`/`misconfig`)
  have no such limit. Older apps may need a modern `pom.xml`/toolchain to compile,
  which does not change their source.
