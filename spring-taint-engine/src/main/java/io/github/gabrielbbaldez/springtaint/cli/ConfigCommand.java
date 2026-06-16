package io.github.gabrielbbaldez.springtaint.cli;

import io.github.gabrielbbaldez.springtaint.configaudit.ConfigAuditScanner;
import io.github.gabrielbbaldez.springtaint.report.ConsoleReporter;
import io.github.gabrielbbaldez.springtaint.report.Finding;
import io.github.gabrielbbaldez.springtaint.report.sarif.SarifWriter;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.Callable;

/**
 * {@code spring-taint config TARGET} — audits Spring configuration files
 * ({@code application*.yml/.properties}) for insecure settings (a pattern-based
 * check, independent of the taint analysis).
 */
@Command(
        name = "config",
        description = "Audit Spring config files (application*.yml/.properties) for insecure settings.")
public final class ConfigCommand implements Callable<Integer> {

    @Parameters(index = "0", paramLabel = "TARGET",
            description = "A config file, or a directory to search for application*.yml/.properties.")
    private Path target;

    @Option(names = {"-o", "--output"}, paramLabel = "FILE",
            description = "Write a SARIF 2.1 report to this file.")
    private Path output;

    @Override
    public Integer call() throws Exception {
        if (target == null || !Files.exists(target)) {
            System.err.println("Target not found: " + target);
            return 2;
        }
        List<Finding> findings = new ConfigAuditScanner().scan(target);
        new ConsoleReporter(System.out, false).report(findings);
        if (output != null) {
            new SarifWriter().write(output, findings);
            System.out.println("SARIF report written to " + output);
        }
        return findings.isEmpty() ? 0 : 1;
    }
}
