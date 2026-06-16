package io.github.gabrielbbaldez.springtaint.nearmiss;

import io.github.gabrielbbaldez.springtaint.report.Finding;
import io.github.gabrielbbaldez.springtaint.report.FlowStep;
import io.github.gabrielbbaldez.springtaint.report.Severity;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Flags <em>near-miss sanitizers</em> — code that attempts to sanitize but does not
 * actually make the data safe. These are more dangerous than missing sanitization,
 * because the developer believes the flow is protected. Source-based (rides on
 * {@code --src}), since the attempt is visible in the code, not the bytecode.
 *
 * <ul>
 *   <li><b>Insufficient</b> — character filtering ({@code replace}/{@code replaceAll})
 *       before a SQL sink does not prevent injection;</li>
 *   <li><b>Blacklist</b> — removing a tag literal before an HTML sink is bypassable;</li>
 *   <li><b>Discarded result</b> — a sanitizer is called but its return value is thrown
 *       away while the original value reaches the sink;</li>
 *   <li><b>Wrong context</b> — {@code htmlEscape} (an XSS sanitizer) used before a
 *       redirect, which it does not protect (a flow the taint engine otherwise treats
 *       as sanitized).</li>
 * </ul>
 */
public final class NearMissAnnotator {

    private static final Pattern REPLACE =
            Pattern.compile("\\.(replaceAll|replaceFirst|replace)\\s*\\(");
    /** A statement that is itself a sanitizer call (no assignment) — its result is discarded. */
    private static final Pattern DISCARDED_SANITIZER =
            Pattern.compile("^(?:[\\w.]*\\.)?(htmlEscape|escapeHtml\\w*|encodeForHTML|escapeSql)\\s*\\([^;]*\\)\\s*;\\s*(?://.*)?$");
    private static final Pattern ESCAPE_ASSIGN =
            Pattern.compile("(\\w+)\\s*=\\s*[\\w.]*htmlEscape\\s*\\(");
    private static final Pattern REDIRECT_USE =
            Pattern.compile("sendRedirect\\s*\\(\\s*(\\w+)");

    /** Lines of skew tolerated between bytecode line numbers and source lines. */
    private static final int PAD = 2;

    public List<Finding> annotate(List<Finding> findings, Path src) throws IOException {
        Map<String, List<String>> sources = readSources(src);
        List<Finding> out = new ArrayList<>();
        for (Finding f : findings) {
            out.add(enrich(f, sources));
        }
        out.addAll(detectWrongContext(sources, findings));
        return out;
    }

    /** Adds a near-miss note to a taint finding whose intra-method flow passes a bad sanitizer. */
    private Finding enrich(Finding f, Map<String, List<String>> sources) {
        FlowStep source = f.source();
        if (source == null || !source.file().equals(f.file())) {
            return f;   // only the intra-method case is handled precisely
        }
        List<String> lines = sources.get(f.file());
        if (lines == null) {
            return f;
        }
        int lo = Math.max(0, Math.min(source.line(), f.line()) - 1 - PAD);
        int hi = Math.min(lines.size(), Math.max(source.line(), f.line()) + PAD);
        boolean replace = false;
        boolean discarded = false;
        for (int i = lo; i < hi; i++) {
            String line = lines.get(i).trim();
            if (DISCARDED_SANITIZER.matcher(line).find()) {
                discarded = true;
            } else if (REPLACE.matcher(line).find()) {
                replace = true;
            }
        }
        String note = noteFor(f.ruleId(), replace, discarded);
        return note == null ? f : f.withNearMiss(note);
    }

    private static String noteFor(String rule, boolean replace, boolean discarded) {
        boolean sql = rule.equals("sql-injection") || rule.equals("jpql-injection");
        if (discarded) {
            return "a sanitizer is called but its result is discarded; assign it and use the escaped value, "
                    + "not the original";
        }
        if (replace && sql) {
            return "character filtering (replace/replaceAll) does not prevent SQL injection "
                    + "(backslash escaping, encodings, SQL functions); use a parameterized query";
        }
        if (replace) {
            return "blacklist filtering (replace/replaceAll) is trivially bypassable "
                    + "(e.g. <scr<script>ipt>); use contextual output escaping such as HtmlUtils.htmlEscape";
        }
        return null;
    }

    /**
     * Detects the wrong-context case: a value HTML-escaped and then redirected. The
     * engine treats htmlEscape as sanitizing, so this flow would otherwise be missed.
     */
    private List<Finding> detectWrongContext(Map<String, List<String>> sources, List<Finding> existing) {
        Set<String> known = new HashSet<>();
        for (Finding f : existing) {
            known.add(f.file() + ":" + f.line());
        }
        List<Finding> out = new ArrayList<>();
        for (Map.Entry<String, List<String>> entry : sources.entrySet()) {
            String file = entry.getKey();
            List<String> lines = entry.getValue();
            Map<String, Integer> escaped = new HashMap<>();
            for (int i = 0; i < lines.size(); i++) {
                Matcher assign = ESCAPE_ASSIGN.matcher(lines.get(i));
                if (assign.find()) {
                    escaped.put(assign.group(1), i + 1);
                }
                Matcher redirect = REDIRECT_USE.matcher(lines.get(i));
                if (redirect.find() && escaped.containsKey(redirect.group(1))) {
                    int line = i + 1;
                    if (known.contains(file + ":" + line)) {
                        continue;
                    }
                    out.add(new Finding("open-redirect", Severity.MEDIUM,
                            "User input is HTML-escaped before a redirect, which does not prevent open redirect",
                            null, file, line,
                            List.of(new FlowStep(file, line, "sink: sendRedirect(escaped url)")))
                            .withNearMiss("htmlEscape protects against XSS, not open redirect; "
                                    + "validate the URL against an allowlist of hosts/paths"));
                }
            }
        }
        return out;
    }

    private static Map<String, List<String>> readSources(Path src) throws IOException {
        Map<String, List<String>> out = new LinkedHashMap<>();
        if (Files.isRegularFile(src)) {
            out.put(src.getFileName().toString(), Files.readAllLines(src));
            return out;
        }
        if (Files.isDirectory(src)) {
            try (Stream<Path> paths = Files.walk(src)) {
                for (Path p : (Iterable<Path>) paths
                        .filter(f -> f.toString().endsWith(".java"))::iterator) {
                    out.putIfAbsent(p.getFileName().toString(), Files.readAllLines(p));
                }
            }
        }
        return out;
    }
}
