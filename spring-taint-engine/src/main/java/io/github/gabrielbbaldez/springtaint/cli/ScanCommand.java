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

import java.io.IOException;
import java.io.InputStream;
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

    @Parameters(index = "0", paramLabel = "TARGET",
            description = "Compiled project to scan: a directory of .class files or a JAR.")
    private Path target;

    @Option(names = {"-c", "--config"}, paramLabel = "FILE",
            description = "Taint configuration (default: ./config/spring-taint.yml, "
                    + "or the bundled default).")
    private Path config;

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

    @Option(names = "--no-default-config",
            description = "With --config, use only that file instead of merging it "
                    + "onto the built-in default rules.")
    private boolean noDefaultConfig;

    @Override
    public Integer call() throws Exception {
        if (target == null || !Files.exists(target)) {
            System.err.println("Target not found: " + target);
            return 2;
        }
        TaintConfig taintConfig = loadConfig();
        if (taintConfig == null) {
            return 2;
        }
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

    /**
     * Loads the taint config. With no {@code --config}, returns the default
     * (./config/spring-taint.yml, else the bundled one). With {@code --config},
     * merges that file onto the default, unless {@code --no-default-config} is set.
     */
    private TaintConfig loadConfig() throws IOException {
        if (config == null) {
            TaintConfig def = loadDefault();
            if (def == null) {
                System.err.println("No taint config found; pass one with --config.");
            }
            return def;
        }
        if (!Files.exists(config)) {
            System.err.println("Config not found: " + config);
            return null;
        }
        TaintConfig user = TaintConfigLoader.load(config);
        if (noDefaultConfig) {
            return user;
        }
        TaintConfig def = loadDefault();
        return def == null ? user : def.mergeWith(user);
    }

    /** The default config: ./config/spring-taint.yml if present, else the one bundled in the jar. */
    private TaintConfig loadDefault() throws IOException {
        Path local = Path.of("config", "spring-taint.yml");
        if (Files.exists(local)) {
            return TaintConfigLoader.load(local);
        }
        try (InputStream bundled = getClass().getResourceAsStream("/spring-taint.yml")) {
            return bundled == null ? null : TaintConfigLoader.load(bundled);
        }
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
