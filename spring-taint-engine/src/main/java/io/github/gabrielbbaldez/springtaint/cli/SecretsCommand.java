package io.github.gabrielbbaldez.springtaint.cli;

import io.github.gabrielbbaldez.springtaint.report.ConsoleReporter;
import io.github.gabrielbbaldez.springtaint.report.Finding;
import io.github.gabrielbbaldez.springtaint.report.sarif.SarifWriter;
import io.github.gabrielbbaldez.springtaint.secrets.SecretScanner;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.Callable;

/**
 * {@code spring-taint secrets TARGET} — scans compiled bytecode for hardcoded
 * secrets (a pattern-based check, independent of the taint analysis).
 */
@Command(
        name = "secrets",
        description = "Scan compiled bytecode (a directory or JAR) for hardcoded secrets.")
public final class SecretsCommand implements Callable<Integer> {

    @Parameters(index = "0", paramLabel = "TARGET",
            description = "Compiled classes directory or JAR to scan.")
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
        List<Finding> findings = new SecretScanner().scan(target);
        new ConsoleReporter(System.out, false).report(findings);
        if (output != null) {
            new SarifWriter().write(output, findings);
            System.out.println("SARIF report written to " + output);
        }
        return findings.isEmpty() ? 0 : 1;
    }
}
