package io.github.gabrielbbaldez.springtaint.cli;

import io.github.gabrielbbaldez.springtaint.config.TaintConfig;
import io.github.gabrielbbaldez.springtaint.config.TaintConfigLoader;
import io.github.gabrielbbaldez.springtaint.engine.AnalysisRequest;
import io.github.gabrielbbaldez.springtaint.engine.TaiETaintEngine;
import io.github.gabrielbbaldez.springtaint.engine.TaintEngine;
import io.github.gabrielbbaldez.springtaint.report.ConsoleReporter;
import io.github.gabrielbbaldez.springtaint.report.Finding;
import io.github.gabrielbbaldez.springtaint.report.sarif.SarifWriter;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.stream.Collectors;

/**
 * {@code spring-taint scan TARGET} — analyses a compiled Spring Boot project.
 */
@Command(
        name = "scan",
        description = "Scan a compiled Spring Boot project for taint vulnerabilities.")
public final class ScanCommand implements Callable<Integer> {

    @Parameters(index = "0", paramLabel = "TARGET",
            description = "Compiled project to scan: a directory of .class files or a JAR.")
    private Path target;

    @Option(names = {"-c", "--config"}, paramLabel = "FILE",
            description = "Taint configuration (default: ./config/spring-taint.yml, "
                    + "or the bundled default).")
    private Path config;

    @Option(names = {"-o", "--output"}, paramLabel = "FILE",
            description = "Write a SARIF 2.1 report to this file.")
    private Path output;

    @Option(names = {"-l", "--libs"}, paramLabel = "CLASSPATH",
            description = "Dependencies needed to resolve the target "
                    + "(e.g. Spring jars), path-separator-joined.")
    private String libs;

    @Option(names = "--severity", split = ",", paramLabel = "LEVEL",
            description = "Only report these severities: critical, high, medium, low.")
    private List<String> severities = new ArrayList<>();

    @Option(names = {"-v", "--verbose"}, description = "Show the full taint trace.")
    private boolean verbose;

    @Option(names = "--no-default-config",
            description = "With --config, use only that file instead of merging it "
                    + "onto the built-in default rules.")
    private boolean noDefaultConfig;

    @Option(names = "--diff", paramLabel = "REF",
            description = "Only report findings whose trace touches a file changed vs REF "
                    + "(e.g. origin/main). Uses 'git diff'; run from the repository.")
    private String diffRef;

    @Option(names = "--src", paramLabel = "DIR",
            description = "Source directory; enables suppression comments, near-miss notes, and fixes.")
    private Path src;

    @Option(names = "--suggest-fixes",
            description = "Show suggested fixes (e.g. parameterized queries) without applying. Needs --src.")
    private boolean suggestFixes;

    @Option(names = "--fix",
            description = "Apply high-confidence fixes to the source files. Needs --src.")
    private boolean fix;

    @Option(names = "--fix-confidence", paramLabel = "LEVEL",
            description = "With --fix: 'high' (default; only short single-method flows) or 'all'.")
    private String fixConfidence = "high";

    @Option(names = "--baseline", paramLabel = "FILE",
            description = "Accept existing findings: if FILE is absent, record the current findings; "
                    + "otherwise report (and gate on) only findings not in it.")
    private Path baseline;

    @Override
    public Integer call() throws Exception {
        if (target == null || !Files.exists(target)) {
            System.err.println("Target not found: " + target);
            return 2;
        }
        TaintConfig taintConfig = loadConfig();
        if (taintConfig == null) {
            return 2;
        }
        AnalysisRequest request = new AnalysisRequest(target, libs, taintConfig, severities, verbose);

        TaintEngine engine = new TaiETaintEngine();
        List<Finding> findings = filter(engine.analyze(request), severities);

        if (diffRef != null && !diffRef.isBlank()) {
            findings = filterToDiff(findings, diffRef);
        }
        if (src != null) {
            findings = new io.github.gabrielbbaldez.springtaint.nearmiss.NearMissAnnotator()
                    .annotate(findings, src);
            findings = applySuppressions(findings, src);
            findings.sort(java.util.Comparator
                    .comparing(Finding::ruleId).thenComparing(Finding::file).thenComparingInt(Finding::line));
        }

        if (baseline != null) {
            findings = applyBaseline(findings, baseline);
        }

        new ConsoleReporter(System.out, verbose).report(findings);

        // Generate autofix patches once (when sources are available) and reuse them for
        // both the console output and the SARIF, so the SARIF diff stays based on the
        // original source even when --fix has already rewritten the files on disk.
        List<io.github.gabrielbbaldez.springtaint.autofix.Patch> patches = (src != null)
                ? new io.github.gabrielbbaldez.springtaint.autofix.AutofixGenerator().generate(findings, src)
                : List.of();

        if (suggestFixes || fix) {
            if (src == null) {
                System.err.println("--suggest-fixes / --fix needs --src <source dir>.");
            } else {
                handleFixes(patches);
            }
        }

        if (output != null) {
            new SarifWriter().withFixes(patches).write(output, findings);
            System.out.println("SARIF report written to " + output);
        }

        // Non-zero exit when vulnerabilities are found, so CI can gate on it.
        return findings.isEmpty() ? 0 : 1;
    }

    /**
     * Loads the taint config. With no {@code --config}, returns the default
     * (./config/spring-taint.yml, else the bundled one). With {@code --config},
     * merges that file onto the default, unless {@code --no-default-config} is set.
     */
    private TaintConfig loadConfig() throws IOException {
        if (config == null) {
            TaintConfig def = loadDefault();
            if (def == null) {
                System.err.println("No taint config found; pass one with --config.");
            }
            return def;
        }
        if (!Files.exists(config)) {
            System.err.println("Config not found: " + config);
            return null;
        }
        TaintConfig user = TaintConfigLoader.load(config);
        if (noDefaultConfig) {
            return user;
        }
        TaintConfig def = loadDefault();
        return def == null ? user : def.mergeWith(user);
    }

    /** The default config: ./config/spring-taint.yml if present, else the one bundled in the jar. */
    private TaintConfig loadDefault() throws IOException {
        Path local = Path.of("config", "spring-taint.yml");
        if (Files.exists(local)) {
            return TaintConfigLoader.load(local);
        }
        try (InputStream bundled = getClass().getResourceAsStream("/spring-taint.yml")) {
            return bundled == null ? null : TaintConfigLoader.load(bundled);
        }
    }

    /**
     * Keeps only findings whose trace touches a file changed against {@code ref}
     * (per {@code git diff --name-only}). A flow is matched if its sink <em>or</em>
     * any step on the path lives in a changed file.
     *
     * <p>Matching is by file name, so a finding may be missed if its source is in an
     * unchanged file and only its sink changed (or vice-versa); run a full scan
     * periodically (e.g. nightly) alongside diff scans on pull requests.
     */
    private List<Finding> filterToDiff(List<Finding> findings, String ref) {
        Set<String> changed = changedFiles(ref);
        if (changed == null) {
            System.err.println("--diff: could not determine changed files; reporting all findings.");
            return findings;
        }
        List<Finding> kept = findings.stream()
                .filter(f -> changed.contains(f.file())
                        || f.flow().stream().anyMatch(s -> changed.contains(s.file())))
                .collect(Collectors.toList());
        System.out.printf("Diff mode: %d of %d finding(s) touch files changed vs %s.%n",
                kept.size(), findings.size(), ref);
        return kept;
    }

    /** Drops findings silenced by an inline {@code // spring-taint: suppress RULE} comment. */
    private List<Finding> applySuppressions(List<Finding> findings, Path sourceDir) throws IOException {
        var suppressions = new io.github.gabrielbbaldez.springtaint.suppress.SuppressionScanner().scan(sourceDir);
        if (suppressions.isEmpty()) {
            return findings;
        }
        List<Finding> kept = findings.stream()
                .filter(f -> !io.github.gabrielbbaldez.springtaint.suppress.SuppressionScanner
                        .isSuppressed(f, suppressions))
                .collect(Collectors.toList());
        int suppressed = findings.size() - kept.size();
        if (suppressed > 0) {
            System.out.printf("Suppressed %d finding(s) via inline // spring-taint: suppress comments.%n",
                    suppressed);
        }
        return kept;
    }

    /** Base names of {@code .java} files changed vs {@code ref}, or {@code null} on error. */
    private static Set<String> changedFiles(String ref) {
        try {
            Process p = new ProcessBuilder("git", "diff", "--name-only", ref).start();
            Set<String> names = new java.util.HashSet<>();
            try (java.io.BufferedReader r = new java.io.BufferedReader(new java.io.InputStreamReader(
                    p.getInputStream(), java.nio.charset.StandardCharsets.UTF_8))) {
                String line;
                while ((line = r.readLine()) != null) {
                    if (line.endsWith(".java")) {
                        names.add(line.substring(line.lastIndexOf('/') + 1));
                    }
                }
            }
            return p.waitFor() == 0 ? names : null;
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            return null;
        }
    }

    /** Generates parameterized-query fixes; shows them, and applies high-confidence ones with --fix. */
    private void handleFixes(List<io.github.gabrielbbaldez.springtaint.autofix.Patch> patches) throws IOException {
        if (patches.isEmpty()) {
            System.out.println("\nNo automatic fixes available.");
            return;
        }
        boolean applyAll = "all".equalsIgnoreCase(fixConfidence);
        java.util.Set<Path> applied = new java.util.HashSet<>();
        System.out.println();
        for (io.github.gabrielbbaldez.springtaint.autofix.Patch p : patches) {
            boolean canApply = fix && (applyAll || p.highConfidence());
            System.out.printf("[%s] %s - %s:%d (%s confidence)%n",
                    canApply ? "fix" : "suggested fix", p.rule(),
                    p.file().getFileName(), p.line(), p.highConfidence() ? "high" : "low");
            System.out.printf("  %s%n", p.description());
            System.out.print(p.diff());
            if (canApply && applied.add(p.file())) {
                Files.writeString(p.file(), p.newSource());
                System.out.println("  applied.");
            } else if (canApply) {
                System.out.println("  skipped: another fix already applied to this file this run; re-run to continue.");
            }
            System.out.println();
        }
        if (!fix) {
            System.out.println("Run with --fix to apply the high-confidence fixes "
                    + "(--fix-confidence all to apply every suggestion).");
        }
    }

    /**
     * On the first run (no baseline file) records the current findings and reports
     * nothing new; on later runs returns only findings absent from the baseline, so a
     * team can adopt the tool on a legacy codebase and gate CI on new issues only.
     */
    private List<Finding> applyBaseline(List<Finding> findings, Path baselineFile) throws IOException {
        if (!Files.exists(baselineFile)) {
            List<String> prints = findings.stream().map(ScanCommand::fingerprint).distinct().sorted().toList();
            Files.write(baselineFile, prints);
            System.out.printf("Baseline written: %d finding(s) recorded in %s. "
                    + "Future runs report only new findings.%n", prints.size(), baselineFile);
            return List.of();
        }
        Set<String> accepted = new java.util.HashSet<>(Files.readAllLines(baselineFile));
        List<Finding> fresh = findings.stream()
                .filter(f -> !accepted.contains(fingerprint(f)))
                .collect(Collectors.toList());
        System.out.printf("Baseline: %d new finding(s), %d baselined.%n",
                fresh.size(), findings.size() - fresh.size());
        return fresh;
    }

    /** A line-independent identity for a finding, so a baseline survives code shifting around. */
    private static String fingerprint(Finding f) {
        String sink = f.sink() != null ? f.sink().description() : f.message();
        return f.ruleId() + "\t" + f.file() + "\t" + sink;
    }

    private static List<Finding> filter(List<Finding> findings, List<String> severities) {
        if (severities.isEmpty()) {
            return findings;
        }
        Set<String> wanted = severities.stream()
                .map(s -> s.toLowerCase(Locale.ROOT))
                .collect(Collectors.toSet());
        return findings.stream()
                .filter(f -> wanted.contains(f.severity().name().toLowerCase(Locale.ROOT)))
                .collect(Collectors.toList());
    }
}
