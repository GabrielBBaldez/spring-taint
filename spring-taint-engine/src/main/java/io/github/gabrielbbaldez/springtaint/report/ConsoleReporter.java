package io.github.gabrielbbaldez.springtaint.report;

import java.io.PrintStream;
import java.util.List;

/**
 * Renders findings to a {@link PrintStream} in a compact, human-readable form.
 */
public final class ConsoleReporter {

    private final PrintStream out;
    private final boolean verbose;

    public ConsoleReporter(PrintStream out, boolean verbose) {
        this.out = out;
        this.verbose = verbose;
    }

    public void report(List<Finding> findings) {
        if (findings.isEmpty()) {
            out.println("No taint vulnerabilities found.");
            return;
        }
        for (Finding f : findings) {
            out.printf("[%s] %s%s%n",
                    f.severity(),
                    f.ruleId(),
                    f.route() == null ? "" : " @ " + f.route());

            if (f.flow().size() <= 1) {
                // single-location finding (e.g. a hardcoded secret) — not a taint flow
                out.printf("  At:      %s%s - %s%n", f.file(), f.line() > 0 ? ":" + f.line() : "", f.message());
            } else {
                FlowStep source = f.source();
                FlowStep sink = f.sink();
                if (source != null) {
                    out.printf("  Source:  %s:%d - %s%n", source.file(), source.line(), source.description());
                }
                if (verbose) {
                    out.println("  Flow:");
                    for (FlowStep step : f.flow()) {
                        out.printf("    -> %s:%d - %s%n", step.file(), step.line(), step.description());
                    }
                }
                if (sink != null) {
                    out.printf("  Sink:    %s:%d - %s%n", sink.file(), sink.line(), sink.description());
                }
                out.println("  Sanitizer: none detected");
            }
            out.println();
        }
        out.printf("%d finding(s).%n", findings.size());
    }
}
