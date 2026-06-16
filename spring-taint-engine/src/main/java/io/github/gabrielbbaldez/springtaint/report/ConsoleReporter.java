package io.github.gabrielbbaldez.springtaint.report;

import java.io.PrintStream;
import java.util.ArrayList;
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
            String route = f.route() == null ? "" : " @ " + f.route();
            List<String> tags = new ArrayList<>();
            if (f.nearMiss() != null) {
                tags.add("near-miss sanitizer");
            }
            if (f.confidence() != null) {
                tags.add("confidence: " + f.confidence() + "%"
                        + (f.confidence() < 50 ? " - review manually" : ""));
            }
            String suffix = tags.isEmpty() ? "" : " (" + String.join(", ", tags) + ")";
            out.printf("[%s] %s%s%s%n", f.severity(), f.ruleId(), route, suffix);

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
            if (f.nearMiss() != null) {
                out.printf("  Near-miss: %s%n", f.nearMiss());
            }
            out.println();
        }
        out.printf("%d finding(s).%n", findings.size());
    }
}
