# Demo app

An intentionally vulnerable Spring Boot 3 application used as a true-positive /
false-positive showcase for Spring Taint Analyzer.

Every category below ships **two** endpoints: a vulnerable one that *should* be
reported, and a safe sibling that *must not* be. A good analyzer flags the first
of each pair and stays silent on the second. **Never deploy this app.**

| Category | Vulnerable endpoint | Safe sibling | Why the sibling is safe |
|----------|---------------------|--------------|-------------------------|
| Reflected XSS | `GET /greet?name=` | `GET /greet-safe?name=` | value is `HtmlUtils.htmlEscape`d before it reaches the writer |
| Command injection | `GET /ping?host=` | `GET /uptime` | the command is a constant with no request data |
| SQL injection (cross-layer) | `DELETE /accounts?owner=` | `DELETE /accounts-safe?owner=` | the service uses a bound `?` parameter instead of string concatenation |

The SQL injection deliberately crosses a layer: the controller hands the request
parameter to `AccountService`, and the concatenation happens one method down in
`AccountService.deleteByOwner`. That exercises the interprocedural part of the
engine rather than a single-method pattern match.

## Build

The app targets Java 17 for broad compatibility, but the engine reads Java 21
application bytecode fine too -- the JDK 17 requirement is the analyzer's own runtime,
not a limit on the scanned code. Build it with any JDK 17+ toolchain:

```bash
mvn -f examples/demo-app/pom.xml clean compile
```

## Scan

```bash
# resolve the runtime classpath once (the source-level sinks need it)
mvn -f examples/demo-app/pom.xml dependency:build-classpath \
    -Dmdep.outputFile=demo-cp.txt

# scan on a JDK 17 runtime
java -jar spring-taint-engine/target/spring-taint-all.jar \
    scan examples/demo-app/target/classes --libs "$(cat demo-cp.txt)"
```

## Expected output

Three findings, one per vulnerable endpoint, and nothing on the safe siblings:

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

If you see more than three findings, one of the safe siblings was flagged: that is
a false positive worth reporting. If you see fewer, a true positive was missed.
