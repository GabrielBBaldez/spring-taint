# Real-world validation

Beyond the synthetic [benchmark](../spring-taint-benchmark/README.md) (which measures
recall and precision against known ground truth), the analyzer is run against real
open-source Spring Boot applications: a clean app to measure **precision** (false
positives on code not written for it) and an intentionally-vulnerable app to measure
**recall** (does it find a real, cross-layer flaw).

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
