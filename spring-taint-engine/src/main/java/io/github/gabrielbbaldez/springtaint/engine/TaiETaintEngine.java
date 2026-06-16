package io.github.gabrielbbaldez.springtaint.engine;

import io.github.gabrielbbaldez.springtaint.config.SanitizerSpec;
import io.github.gabrielbbaldez.springtaint.config.SinkSpec;
import io.github.gabrielbbaldez.springtaint.config.SourceSpec;
import io.github.gabrielbbaldez.springtaint.config.TaintConfig;
import io.github.gabrielbbaldez.springtaint.config.TransferSpec;
import io.github.gabrielbbaldez.springtaint.engine.taie.SpringEntryPointPlugin;
import io.github.gabrielbbaldez.springtaint.engine.taie.SpringLibraryModelPlugin;
import io.github.gabrielbbaldez.springtaint.engine.taie.SpringTaintConfigProvider;
import io.github.gabrielbbaldez.springtaint.report.Finding;
import io.github.gabrielbbaldez.springtaint.report.FlowStep;
import io.github.gabrielbbaldez.springtaint.report.Severity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pascal.taie.World;
import pascal.taie.analysis.pta.PointerAnalysis;
import pascal.taie.analysis.pta.PointerAnalysisResult;
import pascal.taie.analysis.pta.plugin.taint.TaintFlowExtractor;
import pascal.taie.analysis.pta.plugin.taint.TaintFlowExtractor.ExtractedFlow;
import pascal.taie.analysis.pta.plugin.taint.TaintFlowExtractor.Hop;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

/**
 * {@link TaintEngine} backed by <a href="https://github.com/pascal-lab/Tai-e">Tai-e</a>.
 *
 * <p>Runs Tai-e's pointer analysis with the taint plugin over the target's
 * bytecode, contributing the Spring layer through two registrations:
 * <ul>
 *   <li>{@link SpringEntryPointPlugin} — makes annotated handlers reachable;
 *   <li>{@link SpringTaintConfigProvider} — turns annotated parameters into sources.
 * </ul>
 * Sinks, sanitizers and string transfers are supplied as a generated Tai-e
 * taint-config directory. The resulting taint flows are mapped to {@link Finding}s.
 */
public final class TaiETaintEngine implements TaintEngine {

    private static final Logger log = LoggerFactory.getLogger(TaiETaintEngine.class);

    private static final String STRING_TRANSFERS_RESOURCE =
            "/commonly-used-taint-config/transfer/string-transfers.yml";

    @Override
    public List<Finding> analyze(AnalysisRequest request) {
        Path configDir = null;
        Path outputDir = null;
        try {
            configDir = Files.createTempDirectory("spring-taint-cfg");
            outputDir = Files.createTempDirectory("spring-taint-out");
            writeTaintConfig(request.config(), configDir);
            Map<String, String> vulnByMethod = buildVulnMap(request.config());

            String[] args = buildTaiEArguments(request, configDir, outputDir);
            log.info("Running Tai-e: {}", String.join(" ", args));
            pascal.taie.Main.main(args);

            List<ExtractedFlow> flows = TaintFlowExtractor.extract(getPointerAnalysisResult());
            log.info("Tai-e reported {} taint flow(s)", flows.size());

            List<Finding> findings = new ArrayList<>();
            for (ExtractedFlow flow : flows) {
                findings.add(toFinding(flow, vulnByMethod));
            }
            findings.sort(Comparator
                    .comparing(Finding::ruleId)
                    .thenComparing(Finding::file)
                    .thenComparingInt(Finding::line));
            return findings;
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to prepare Tai-e configuration", e);
        } finally {
            deleteQuietly(outputDir);
            deleteQuietly(configDir);
        }
    }

    private String[] buildTaiEArguments(AnalysisRequest request, Path configDir, Path outputDir) {
        // only-app keeps the analysis in application code: Spring/JDBC internals are
        // modelled through the taint config (sources/sinks/transfers) rather than
        // analysed, which is both correct for our purpose and avoids diving into the
        // framework's optional dependencies.
        String ptaOptions = "only-app:true"
                // Java 17 compiles string concatenation to invokedynamic
                // (makeConcatWithConstants); model it so taint flows through "a" + tainted.
                + ";handle-invokedynamic:true"
                // Keep string objects distinct so a sanitizer's clean result is not
                // merged with the tainted input (otherwise htmlEscape would be a no-op).
                + ";merge-string-objects:false"
                + ";taint-config:" + posix(configDir)
                + ";taint-config-providers:[" + SpringTaintConfigProvider.class.getName() + "]"
                + ";plugins:[" + SpringEntryPointPlugin.class.getName()
                + "," + SpringLibraryModelPlugin.class.getName() + "]";

        List<String> args = new ArrayList<>();
        args.add("-pp");                       // model the JDK with the current JVM
        args.add("--allow-phantom");           // tolerate Spring's optional/missing deps
        args.add("-acp");
        args.add(request.target().toString()); // target classes = application code
        if (request.libraryClasspath() != null && !request.libraryClasspath().isBlank()) {
            args.add("-cp");
            args.add(request.libraryClasspath()); // dependencies (Spring, JDBC, …)
        }
        args.add("--output-dir");
        args.add(outputDir.toString());
        args.add("-a");
        args.add("pta=" + ptaOptions);
        return args.toArray(new String[0]);
    }

    /**
     * Writes the Tai-e taint-config directory: our sinks/sanitizers plus Tai-e's
     * bundled string transfers (required for taint to flow through string
     * concatenation, which compiles to {@code StringBuilder} calls).
     */
    private void writeTaintConfig(TaintConfig config, Path dir) throws IOException {
        StringBuilder yaml = new StringBuilder();
        // Concrete-method sources (returned value or parameter tainted). Annotation-driven
        // Spring sources are contributed separately by SpringTaintConfigProvider; Tai-e
        // unions both. The index keyword (result) and parameter indices pass through as-is.
        if (!config.sources().isEmpty()) {
            yaml.append("sources:\n");
            for (SourceSpec source : config.sources()) {
                yaml.append("  - { kind: ").append(source.kind())
                        .append(", method: \"").append(source.method())
                        .append("\", index: ").append(source.index()).append(" }\n");
            }
        }
        yaml.append("sinks:\n");
        for (SinkSpec sink : config.sinks()) {
            yaml.append("  - { method: \"").append(sink.method())
                    .append("\", index: \"").append(sink.index()).append("\" }\n");
        }
        // Tai-e's ParamSanitizer is parameter-based (index >= 0). A "result"/"base"
        // sanitizer (e.g. HtmlUtils.htmlEscape) is instead modelled as the absence
        // of a taint transfer, so it needs no entry here — skip non-parameter ones.
        List<SanitizerSpec> paramSanitizers = config.sanitizers().stream()
                .filter(s -> isParamIndex(s.index()))
                .toList();
        if (!paramSanitizers.isEmpty()) {
            yaml.append("sanitizers:\n");
            for (SanitizerSpec sanitizer : paramSanitizers) {
                yaml.append("  - { method: \"").append(sanitizer.method())
                        .append("\", index: \"").append(sanitizer.index()).append("\" }\n");
            }
        }
        if (!config.transfers().isEmpty()) {
            yaml.append("transfers:\n");
            for (TransferSpec transfer : config.transfers()) {
                // from/to are bare tokens (base | result | parameter index), matching
                // Tai-e's own transfer files; quoting a numeric index would change its type.
                yaml.append("  - { method: \"").append(transfer.method())
                        .append("\", from: ").append(transfer.from())
                        .append(", to: ").append(transfer.to());
                if (transfer.type() != null && !transfer.type().isBlank()) {
                    yaml.append(", type: \"").append(transfer.type()).append('"');
                }
                yaml.append(" }\n");
            }
        }
        Files.writeString(dir.resolve("spring-sinks.yml"), yaml.toString());

        try (InputStream in = getClass().getResourceAsStream(STRING_TRANSFERS_RESOURCE)) {
            if (in != null) {
                Files.copy(in, dir.resolve("string-transfers.yml"));
            } else {
                log.warn("Bundled string transfers not found on classpath ({}); "
                        + "taint may not flow through string concatenation", STRING_TRANSFERS_RESOURCE);
            }
        }
    }

    /** The pointer analysis result Tai-e stored in the World (taint flows + call graph). */
    private PointerAnalysisResult getPointerAnalysisResult() {
        try {
            return World.get().getResult(PointerAnalysis.ID);
        } catch (RuntimeException e) {
            log.warn("Could not read pointer analysis result from Tai-e: {}", e.toString());
            return null;
        }
    }

    private Finding toFinding(ExtractedFlow flow, Map<String, String> vulnByMethod) {
        String key = flow.sinkMethodClass() + "#" + flow.sinkMethodName();
        String vuln = vulnByMethod.getOrDefault(key, "taint");
        Severity severity = severityFor(vuln);

        List<FlowStep> trace = new ArrayList<>();
        trace.add(new FlowStep(flow.sourceClass() + ".java", flow.sourceLine(),
                "source: " + flow.sourceMethod() + "() - tainted parameter"));
        // Intermediate hops on the call path (the first/last path methods are the
        // source and sink containers, already shown as the source/sink steps).
        List<Hop> hops = flow.trace();
        for (int i = 1; i < hops.size() - 1; i++) {
            Hop hop = hops.get(i);
            trace.add(new FlowStep(hop.className() + ".java", hop.line(),
                    "via " + hop.className() + "." + hop.methodName() + "()"));
        }
        trace.add(new FlowStep(flow.sinkClass() + ".java", flow.sinkLine(),
                "sink: " + flow.sinkMethodName() + "()"));

        String message = "Tainted data reaches " + flow.sinkMethodName() + " (" + vuln + ")";
        return new Finding(vuln, severity, message, null,
                flow.sinkClass() + ".java", flow.sinkLine(), trace, confidence(vuln, hops));
    }

    /** High-confidence categories: concrete, well-known sinks for a real injection. */
    private static final java.util.Set<String> STRONG_SINKS = java.util.Set.of(
            "sql-injection", "jpql-injection", "command-injection", "spel-injection",
            "jndi-injection", "template-injection", "path-traversal", "xxe");

    /**
     * A 0-100 confidence that a taint finding is real, from signals on the call path.
     * Our engine reports no false positives on the benchmark, so this mainly conveys
     * how many assumptions a flow makes in real-world code: short, lambda-free paths
     * into a concrete injection sink are the most certain.
     */
    private static int confidence(String vuln, List<Hop> hops) {
        int score = 70;
        int intermediate = Math.max(0, hops.size() - 2);   // hops excluding source and sink
        if (intermediate == 0) {
            score += 20;
        } else if (intermediate <= 2) {
            score += 10;
        } else if (intermediate >= 5) {
            score -= 15;
        }
        if (STRONG_SINKS.contains(vuln)) {
            score += 10;
        }
        // A lambda on the path leans on Tai-e's partial lambda support — less certain.
        boolean lambda = hops.stream().anyMatch(h ->
                h.methodName().contains("lambda$") || h.className().contains("Lambda"));
        if (lambda) {
            score -= 15;
        }
        return Math.max(10, Math.min(99, score));
    }

    /** Maps each sink method (by declaring class + name) to its vulnerability category. */
    private static Map<String, String> buildVulnMap(TaintConfig config) {
        Map<String, String> map = new HashMap<>();
        for (SinkSpec sink : config.sinks()) {
            String signature = sink.method();
            try {
                String body = signature.substring(signature.indexOf('<') + 1, signature.lastIndexOf('>'));
                String declaringClass = body.substring(0, body.indexOf(':')).trim();
                String afterColon = body.substring(body.indexOf(':') + 1).trim();
                String beforeParen = afterColon.substring(0, afterColon.indexOf('('));
                String name = beforeParen.substring(beforeParen.lastIndexOf(' ') + 1).trim();
                map.put(declaringClass + "#" + name, sink.vuln());
            } catch (RuntimeException e) {
                log.warn("Could not parse sink signature: {}", signature);
            }
        }
        return map;
    }

    private static Severity severityFor(String vuln) {
        return switch (vuln) {
            case "sql-injection", "jpql-injection", "command-injection", "spel-injection",
                 "jndi-injection", "template-injection" -> Severity.CRITICAL;
            case "xss", "path-traversal", "ssrf", "xxe" -> Severity.HIGH;
            case "open-redirect" -> Severity.MEDIUM;
            case "log-injection" -> Severity.LOW;
            default -> Severity.HIGH;
        };
    }

    private static boolean isParamIndex(String index) {
        try {
            return Integer.parseInt(index.trim()) >= 0;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private static String posix(Path path) {
        return path.toAbsolutePath().toString().replace('\\', '/');
    }

    private static void deleteQuietly(Path dir) {
        if (dir == null) {
            return;
        }
        try (Stream<Path> paths = Files.walk(dir)) {
            paths.sorted(Comparator.reverseOrder()).forEach(p -> {
                try {
                    Files.deleteIfExists(p);
                } catch (IOException ignored) {
                    // best effort
                }
            });
        } catch (IOException ignored) {
            // best effort
        }
    }
}
