package io.github.gabrielbbaldez.springtaint.cli;

import io.github.gabrielbbaldez.springtaint.misconfig.MisconfigScanner;
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
 * {@code spring-taint misconfig TARGET} — scans compiled bytecode for insecure
 * Spring patterns (disabled CSRF / clickjacking protection, over-permissive CORS,
 * insecure cookies, sensitive data logged). Pattern-based, independent of taint.
 */
@Command(
        name = "misconfig",
        description = "Scan compiled bytecode for insecure Spring security patterns.")
public final class MisconfigCommand implements Callable<Integer> {

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
        List<Finding> findings = new MisconfigScanner().scan(target);
        new ConsoleReporter(System.out, false).report(findings);
        if (output != null) {
            new SarifWriter().write(output, findings);
            System.out.println("SARIF report written to " + output);
        }
        return findings.isEmpty() ? 0 : 1;
    }
}
