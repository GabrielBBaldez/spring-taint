# Contributing

Thanks for your interest in improving Spring Taint Analyzer! This guide covers the
dev setup, how to add a benchmark case, and the pull-request checklist.

## Requirements

- **JDK 17** — the project compiles to Java 17, and **the analyzer must run on a
  JDK 17 runtime** (Tai-e's invokedynamic handling trips on the JDK 21 runtime
  library). The *application under analysis* can be compiled with a newer JDK —
  Java 21 application bytecode is read fine. You can build with any JDK 17+, but
  run scans with Java 17.
- **Maven 3.9+**

## Build and test

```bash
mvn clean package          # builds the engine + benchmark and runs unit tests
```

This produces the self-contained `spring-taint-engine/target/spring-taint-all.jar`.

## Run the analyzer on the benchmark

```bash
# resolve the benchmark's dependency classpath
mvn -pl spring-taint-benchmark dependency:build-classpath \
  -DincludeScope=test -Dmdep.outputFile=bench-cp.txt

# scan (run with a JDK 17 runtime)
java -jar spring-taint-engine/target/spring-taint-all.jar scan \
  spring-taint-benchmark/target/classes \
  --libs "$(cat spring-taint-benchmark/bench-cp.txt)"
```

It should report **30 findings** (30/30 vulnerable cases, 0 false positives).

## Project layout

- `spring-taint-engine/` — CLI, config model, Tai-e adapter, SARIF reporter. The
  Spring layer lives in `engine/taie/` (entry points, source/sink generation,
  library modelling); `pascal/taie/.../TaintFlowExtractor` bridges Tai-e's
  package-private types.
- `spring-taint-benchmark/` — intentionally vulnerable/safe cases + `expected.yml`.
- `config/spring-taint.yml` — default sources/sinks/sanitizers/transfers.
- `docs/rules.md` — per-rule reference.

## Adding a benchmark case

1. Create a small, **compilable** component under the matching category package in
   `spring-taint-benchmark`.
2. Mark the flow with `taint-source:` / `taint-sink:` comments.
3. Add an entry to [`spring-taint-benchmark/expected.yml`](spring-taint-benchmark/expected.yml)
   (`expected: true` for a real flow, `expected: false` for a safe one) and update
   the `summary` totals.
4. Re-run the scan and confirm the case behaves as expected.

## Adding a rule (source / sink / sanitizer)

Edit [`config/spring-taint.yml`](config/spring-taint.yml) in Tai-e's YAML format.
Method signatures are `<fully.qualified.Class: ReturnType method(ParamTypes)>`, and
`index` is `result`, `base` (the receiver), or a parameter index (`0`, `1`, …):

```yaml
# call source — the returned value is tainted
sources:
  - { kind: call, method: "<com.acme.LegacyInput: java.lang.String read()>", index: result }

# sink — tainted data must not reach this parameter
sinks:
  - { vuln: sql-injection, method: "<com.acme.Dao: void raw(java.lang.String)>", index: 0 }

# sanitizer — taint is cleared at the sanitized argument
sanitizers:
  - { method: "<com.acme.Encoder: java.lang.String clean(java.lang.String)>", index: 0 }

# transfer — taint flows from `from` to `to` (use `type` if an Object result is cast)
transfers:
  - { method: "<com.acme.Box: java.lang.Object get()>", from: base, to: result, type: java.lang.String }
```

Sinks on interface library types (no implementation on the classpath) are matched via
`call-site-mode`. Annotation-driven sources (`@RequestParam`-style) are added to the
engine's source layer (`engine/taie/SpringSources.java`) rather than the YAML. Validate
a custom config with `spring-taint validate-config <file> --classpath <cp>`, and
document the rule in [`docs/rules.md`](docs/rules.md).

## Pull-request checklist

- [ ] `mvn clean package` passes (build + unit tests).
- [ ] The benchmark still detects **30/30 with 0 false positives** (or `expected.yml`
      is updated with the new ground truth).
- [ ] Docs updated (`README.md`, `docs/rules.md`, benchmark `README.md`) if behavior changed.
- [ ] Commit messages are clear and describe *why*, not just *what*.

## Reporting bugs and ideas

Open an issue using the templates. For security vulnerabilities, see
[SECURITY.md](SECURITY.md) — please do **not** open a public issue.
