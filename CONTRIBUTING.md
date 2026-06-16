# Contributing

Thanks for your interest in improving Spring Taint Analyzer! This guide covers the
dev setup, how to add a benchmark case, and the pull-request checklist.

## Requirements

- **JDK 17** — the project compiles to Java 17, and **the analysis must run on a
  JDK 17 runtime**: Tai-e 0.5.1's bytecode frontend cannot read JDK 21 class files.
  You can build with any JDK 17+, but run scans with Java 17.
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

It should report **17 findings** (17/17 vulnerable cases, 0 false positives).

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
Sinks on interface library types are matched via `call-site-mode`. New source
annotations are recognized by the engine's source layer. Document the rule in
[`docs/rules.md`](docs/rules.md).

## Pull-request checklist

- [ ] `mvn clean package` passes (build + unit tests).
- [ ] The benchmark still detects **17/17 with 0 false positives** (or `expected.yml`
      is updated with the new ground truth).
- [ ] Docs updated (`README.md`, `docs/rules.md`, benchmark `README.md`) if behavior changed.
- [ ] Commit messages are clear and describe *why*, not just *what*.

## Reporting bugs and ideas

Open an issue using the templates. For security vulnerabilities, see
[SECURITY.md](SECURITY.md) — please do **not** open a public issue.
