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
 */
public record Finding(
        String ruleId,
        Severity severity,
        String message,
        String route,
        String file,
        int line,
        List<FlowStep> flow,
        Integer confidence) {

    public Finding {
        flow = (flow == null) ? List.of() : List.copyOf(flow);
    }

    /** Creates a finding without a confidence score (pattern-based checks). */
    public Finding(String ruleId, Severity severity, String message, String route,
                   String file, int line, List<FlowStep> flow) {
        this(ruleId, severity, message, route, file, line, flow, null);
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
