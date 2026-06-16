package io.github.gabrielbbaldez.springtaint.suppress;

import io.github.gabrielbbaldez.springtaint.report.Finding;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Reads inline suppression comments from source files. A finding can be silenced
 * with a documented reason:
 *
 * <pre>{@code
 * // spring-taint: suppress sql-injection - tableName comes from an internal enum
 * jdbcTemplate.execute("SELECT * FROM " + table.getValue());
 * }</pre>
 *
 * <p>Use {@code *} as the rule to suppress any finding on the line. The comment may
 * sit on the flagged line or the line directly above it. Because {@code @SuppressWarnings}
 * has source retention (it is absent from bytecode), suppression is comment-based and
 * needs the sources ({@code --src}).
 */
public final class SuppressionScanner {

    /** One suppression directive found in source. */
    public record Suppression(String file, int line, String rule, String reason) {
    }

    private static final Pattern DIRECTIVE = Pattern.compile(
            "//\\s*spring-taint:\\s*suppress\\s+(\\S+)\\s*(?:[-—]\\s*(.*))?", Pattern.CASE_INSENSITIVE);

    /** All suppression directives under {@code src} (a file or a directory of sources). */
    public List<Suppression> scan(Path src) throws IOException {
        List<Suppression> out = new ArrayList<>();
        if (Files.isRegularFile(src)) {
            collect(src, out);
        } else if (Files.isDirectory(src)) {
            try (Stream<Path> paths = Files.walk(src)) {
                for (Path p : (Iterable<Path>) paths
                        .filter(f -> f.toString().endsWith(".java"))::iterator) {
                    collect(p, out);
                }
            }
        }
        return out;
    }

    private void collect(Path file, List<Suppression> out) throws IOException {
        String name = file.getFileName().toString();
        List<String> lines = Files.readAllLines(file);
        for (int i = 0; i < lines.size(); i++) {
            Matcher m = DIRECTIVE.matcher(lines.get(i));
            if (m.find()) {
                String reason = m.group(2) == null ? "" : m.group(2).trim();
                out.add(new Suppression(name, i + 1, m.group(1), reason));
            }
        }
    }

    /**
     * Whether {@code finding} is suppressed by any directive: same file, matching
     * rule (or {@code *}), with the comment on the finding's line or the one above.
     */
    public static boolean isSuppressed(Finding finding, List<Suppression> suppressions) {
        for (Suppression s : suppressions) {
            boolean sameFile = s.file().equals(finding.file());
            boolean ruleMatches = s.rule().equals("*") || s.rule().equals(finding.ruleId());
            boolean nearLine = s.line() == finding.line() || s.line() == finding.line() - 1;
            if (sameFile && ruleMatches && nearLine) {
                return true;
            }
        }
        return false;
    }
}
