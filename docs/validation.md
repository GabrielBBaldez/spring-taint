# Real-world validation

Beyond the synthetic [benchmark](../spring-taint-benchmark/README.md) (which measures
recall and precision against known ground truth), the analyzer is run against real
open-source Spring Boot applications to measure its **false-positive rate on code that
was not written for it**.

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

Recall (finding real vulnerabilities) is covered by the benchmark (33/33, 0 FP); a
validation run against an intentionally-vulnerable real application is future work.

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
