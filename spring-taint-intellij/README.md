# Spring Taint - IntelliJ plugin

IntelliJ IDEA plugin that runs the [spring-taint](https://github.com/GabrielBBaldez/spring-taint)
analyzer on the open project and surfaces the findings inside the IDE.

> **Status: working first slice.** Run **Tools > Run Spring Taint Scan**: the plugin runs
> the bundled analyzer on the open project's compiled module (in a background task), parses
> the SARIF, and lists the findings in a *Spring Taint* tool window -- severity, rule,
> `file:line`, and an `autofix` marker. Double-click a finding to jump to the sink. The
> taint scan needs a registered **JDK 17** SDK (the plugin tells you if none is found).
> Next: render the suggested-fix diff in the panel and offer autofix as an editor quick-fix.

## Approach

The plugin **reuses the existing engine** instead of reimplementing the analysis on the
IDE's PSI: it invokes the self-contained `spring-taint` jar and renders its SARIF output.
The pattern scanners (`secrets` / `misconfig` / `config`) run on any JDK; the taint scan
needs a JDK 17 runtime (the Tai-e frontend limit), which the plugin locates or prompts
for.

## Build

Requires JDK 21 (the IntelliJ 2024.3 toolchain). The plugin bundles the analyzer jar, so
build the engine (a Maven module) first:

```bash
mvn -pl spring-taint-engine -am package   # from the repo root -- produces the engine jar
./gradlew buildPlugin                      # installable zip under build/distributions/
./gradlew runIde                           # sandbox IDE with the plugin installed
```

Built on the [IntelliJ Platform Gradle Plugin](https://github.com/JetBrains/intellij-platform-gradle-plugin) 2.x.
