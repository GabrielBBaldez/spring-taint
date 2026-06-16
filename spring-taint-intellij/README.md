# Spring Taint - IntelliJ plugin

IntelliJ IDEA plugin that runs the [spring-taint](https://github.com/GabrielBBaldez/spring-taint)
analyzer on the open project and surfaces the findings inside the IDE.

> **Status: early scaffold.** The plugin loads, registers a *Spring Taint* tool window
> and a **Tools > Run Spring Taint Scan** action. Running the analyzer and rendering the
> source-to-sink flows (with click-to-navigate and autofix as a quick-fix) is being
> wired next.

## Approach

The plugin **reuses the existing engine** instead of reimplementing the analysis on the
IDE's PSI: it invokes the self-contained `spring-taint` jar and renders its SARIF output.
The pattern scanners (`secrets` / `misconfig` / `config`) run on any JDK; the taint scan
needs a JDK 17 runtime (the Tai-e frontend limit), which the plugin locates or prompts
for.

## Build

Requires JDK 21 (the IntelliJ 2024.3 toolchain).

```bash
./gradlew buildPlugin   # builds the installable zip under build/distributions/
./gradlew runIde        # launches a sandbox IDE with the plugin installed
```

Built on the [IntelliJ Platform Gradle Plugin](https://github.com/JetBrains/intellij-platform-gradle-plugin) 2.x.
