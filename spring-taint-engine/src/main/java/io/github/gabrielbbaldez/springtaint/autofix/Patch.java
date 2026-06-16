package io.github.gabrielbbaldez.springtaint.autofix;

import java.nio.file.Path;

/**
 * A suggested source edit that fixes a finding.
 *
 * @param file           the source file to edit
 * @param line           the sink line the fix addresses
 * @param rule           the vulnerability category being fixed
 * @param description    one-line summary of the fix
 * @param diff           a human-readable unified-style diff (for {@code --suggest-fixes})
 * @param newSource      the full rewritten file content (for {@code --fix})
 * @param highConfidence whether the fix is safe to apply automatically (a short,
 *                       single-method flow); low-confidence fixes are only suggested
 */
public record Patch(
        Path file,
        int line,
        String rule,
        String description,
        String diff,
        String newSource,
        boolean highConfidence) {
}
