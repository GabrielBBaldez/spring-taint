package io.github.gabrielbbaldez.springtaint.report;

/**
 * Severity of a finding, with its mapping to a SARIF {@code result.level}.
 */
public enum Severity {

    CRITICAL("error"),
    HIGH("error"),
    MEDIUM("warning"),
    LOW("note");

    private final String sarifLevel;

    Severity(String sarifLevel) {
        this.sarifLevel = sarifLevel;
    }

    /** The SARIF 2.1 {@code level} string for this severity. */
    public String sarifLevel() {
        return sarifLevel;
    }
}
