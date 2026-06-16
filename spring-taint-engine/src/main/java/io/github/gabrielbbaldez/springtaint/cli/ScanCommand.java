package io.github.gabrielbbaldez.springtaint.cli;

import io.github.gabrielbbaldez.springtaint.config.TaintConfig;
import io.github.gabrielbbaldez.springtaint.config.TaintConfigLoader;
import io.github.gabrielbbaldez.springtaint.engine.AnalysisRequest;
import io.github.gabrielbbaldez.springtaint.engine.TaiETaintEngine;
import io.github.gabrielbbaldez.springtaint.engine.TaintEngine;
import io.github.gabrielbbaldez.springtaint.report.ConsoleReporter;
import io.github.gabrielbbaldez.springtaint.report.Finding;
import io.github.gabrielbbaldez.springtaint.report.sarif.SarifWriter;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.stream.Collectors;

/**
 * {@code spring-taint scan TARGET} — analyses a compiled Spring Boot project.
 */
@Command(
        name = "scan",
        description = "Scan a compiled Spring Boot project for taint vulnerabilities.")
public final class ScanCommand implements Callable<Integer> {

    private static final Path DEFAULT_CONFIG = Path.of("config", "spring-taint.yml");

    @Parameters(index = "0", paramLabel = "TARGET",
            description = "Compiled project to scan: a directory of .class files or a JAR.")
    private Path target;

    @Option(names = {"-c", "--config"}, paramLabel = "FILE",
            description = "Taint configuration (default: ${DEFAULT-VALUE}).")
    private Path config = DEFAULT_CONFIG;

    @Option(names = {"-o", "--output"}, paramLabel = "FILE",
            description = "Write a SARIF 2.1 report to this file.")
    private Path output;

    @Option(names = {"-l", "--libs"}, paramLabel = "CLASSPATH",
            description = "Dependencies needed to resolve the target "
                    + "(e.g. Spring jars), path-separator-joined.")
    private String libs;

    @Option(names = "--severity", split = ",", paramLabel = "LEVEL",
            description = "Only report these severities: critical, high, medium, low.")
    private List<String> severities = new ArrayList<>();

    @Option(names = {"-v", "--verbose"}, description = "Show the full taint trace.")
    private boolean verbose;

    @Override
    public Integer call() throws Exception {
        if (target == null || !Files.exists(target)) {
            System.err.println("Target not found: " + target);
            return 2;
        }
        if (!Files.exists(config)) {
            System.err.println("Config not found: " + config + " (pass one with --config)");
            return 2;
        }

        TaintConfig taintConfig = TaintConfigLoader.load(config);
        AnalysisRequest request = new AnalysisRequest(target, libs, taintConfig, severities, verbose);

        TaintEngine engine = new TaiETaintEngine();
        List<Finding> findings = filter(engine.analyze(request), severities);

        new ConsoleReporter(System.out, verbose).report(findings);

        if (output != null) {
            new SarifWriter().write(output, findings);
            System.out.println("SARIF report written to " + output);
        }

        // Non-zero exit when vulnerabilities are found, so CI can gate on it.
        return findings.isEmpty() ? 0 : 1;
    }

    private static List<Finding> filter(List<Finding> findings, List<String> severities) {
        if (severities.isEmpty()) {
            return findings;
        }
        Set<String> wanted = severities.stream()
                .map(s -> s.toLowerCase(Locale.ROOT))
                .collect(Collectors.toSet());
        return findings.stream()
                .filter(f -> wanted.contains(f.severity().name().toLowerCase(Locale.ROOT)))
                .collect(Collectors.toList());
    }
}
