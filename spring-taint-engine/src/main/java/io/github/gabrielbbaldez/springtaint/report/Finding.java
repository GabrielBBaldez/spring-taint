package io.github.gabrielbbaldez.springtaint.report;

import java.util.List;

/**
 * A single taint vulnerability: an untrusted value reaching a sink without a
 * sanitizer on the path.
 *
 * @param ruleId     vulnerability category, e.g. {@code "sql-injection"}
 * @param severity   finding severity
 * @param message    short human-readable summary
 * @param route      HTTP route or entry point, e.g. {@code "GET /users/search"} (nullable)
 * @param file       file containing the sink
 * @param line       line of the sink
 * @param flow       ordered trace from source to sink
 * @param confidence 0-100 confidence that the finding is real, or {@code null} when
 *                   not applicable (e.g. direct pattern matches like secrets)
 * @param nearMiss   an explanation when the flow passes an <em>attempted</em> but
 *                   incorrect sanitization (e.g. quote-stripping for SQL), or
 *                   {@code null} when there is no such attempt
 */
public record Finding(
        String ruleId,
        Severity severity,
        String message,
        String route,
        String file,
        int line,
        List<FlowStep> flow,
        Integer confidence,
        String nearMiss) {

    public Finding {
        flow = (flow == null) ? List.of() : List.copyOf(flow);
    }

    /** Creates a finding with a confidence score but no near-miss note. */
    public Finding(String ruleId, Severity severity, String message, String route,
                   String file, int line, List<FlowStep> flow, Integer confidence) {
        this(ruleId, severity, message, route, file, line, flow, confidence, null);
    }

    /** Creates a finding without a confidence score (pattern-based checks). */
    public Finding(String ruleId, Severity severity, String message, String route,
                   String file, int line, List<FlowStep> flow) {
        this(ruleId, severity, message, route, file, line, flow, null, null);
    }

    /** Returns a copy of this finding tagged with a near-miss-sanitizer explanation. */
    public Finding withNearMiss(String note) {
        return new Finding(ruleId, severity, message, route, file, line, flow, confidence, note);
    }

    /** The source step (first element of the flow), or {@code null} if the flow is empty. */
    public FlowStep source() {
        return flow.isEmpty() ? null : flow.get(0);
    }

    /** The sink step (last element of the flow), or {@code null} if the flow is empty. */
    public FlowStep sink() {
        return flow.isEmpty() ? null : flow.get(flow.size() - 1);
    }
}
