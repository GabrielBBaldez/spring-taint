package io.github.gabrielbbaldez.springtaint.report;

/**
 * One step in a taint flow, from source through propagators to the sink.
 *
 * @param file        source file the step occurs in
 * @param line        line number of the step
 * @param description human-readable description (e.g. {@code "@RequestParam String name"})
 */
public record FlowStep(String file, int line, String description) {
}
