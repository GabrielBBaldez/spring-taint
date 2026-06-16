package io.github.gabrielbbaldez.springtaint.configaudit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import io.github.gabrielbbaldez.springtaint.report.Finding;
import io.github.gabrielbbaldez.springtaint.report.FlowStep;
import io.github.gabrielbbaldez.springtaint.report.Severity;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Scans Spring configuration files ({@code application*.yml/.yaml/.properties},
 * {@code bootstrap*}) for insecure settings — a pattern-based analysis, separate
 * from taint. Detects:
 * <ul>
 *   <li>hardcoded secrets (a secret-named key with a literal value, not {@code ${...}});</li>
 *   <li>disabled TLS ({@code server.ssl.enabled: false}, insecure trust managers);</li>
 *   <li>Spring Security auto-configuration excluded;</li>
 *   <li>over-broad Actuator exposure ({@code include: "*"});</li>
 *   <li>the H2 console enabled (especially with {@code web-allow-others}).</li>
 * </ul>
 */
public final class ConfigAuditScanner {

    private static final ObjectMapper YAML = new ObjectMapper(new YAMLFactory());

    private static final Pattern SECRET_KEY = Pattern.compile(
            "(?i)(pass(word|wd)?|secret|api[_-]?key|apikey|access[_-]?key|"
            + "private[_-]?key|token|credential)");

    /** Known secret value formats → critical (mirrors the bytecode secrets scanner). */
    private static final List<Pattern> SECRET_VALUE = List.of(
            Pattern.compile("AKIA[0-9A-Z]{16}"),
            Pattern.compile("-----BEGIN [A-Z ]*PRIVATE KEY-----"),
            Pattern.compile("gh[pousr]_[A-Za-z0-9]{20,}"),
            Pattern.compile("xox[baprs]-[A-Za-z0-9-]{10,}"),
            Pattern.compile("sk-[A-Za-z0-9]{16,}"));

    public List<Finding> scan(Path target) throws IOException {
        List<Finding> findings = new ArrayList<>();
        for (Path f : configFiles(target)) {
            findings.addAll(scanFile(f));
        }
        return findings;
    }

    private static List<Path> configFiles(Path target) throws IOException {
        if (Files.isRegularFile(target)) {
            return List.of(target);
        }
        try (Stream<Path> paths = Files.walk(target)) {
            return paths.filter(Files::isRegularFile)
                    .filter(ConfigAuditScanner::isConfigFile)
                    .toList();
        }
    }

    private static boolean isConfigFile(Path p) {
        String n = p.getFileName().toString();
        boolean springName = n.startsWith("application") || n.startsWith("bootstrap");
        return springName && (n.endsWith(".yml") || n.endsWith(".yaml") || n.endsWith(".properties"));
    }

    private List<Finding> scanFile(Path file) throws IOException {
        List<String> lines = Files.readAllLines(file);
        String name = file.getFileName().toString();
        Map<String, String> flat = name.endsWith(".properties")
                ? parseProperties(lines)
                : flattenYaml(file);

        List<Finding> out = new ArrayList<>();
        for (Map.Entry<String, String> e : flat.entrySet()) {
            check(name, e.getKey(), e.getValue(), lines, out);
        }
        return out;
    }

    private void check(String file, String key, String value, List<String> lines, List<Finding> out) {
        String leaf = key.substring(key.lastIndexOf('.') + 1);
        String lower = value.toLowerCase();

        // 1. Hardcoded secret: secret-named key with a literal (non-placeholder) value.
        if (SECRET_KEY.matcher(leaf).find() && isLiteralSecret(value)) {
            boolean known = SECRET_VALUE.stream().anyMatch(p -> p.matcher(value).find());
            add(out, "hardcoded-secret", known ? Severity.CRITICAL : Severity.HIGH, file, line(lines, key, value),
                    "Hardcoded secret in '" + key + "' (" + mask(value) + ") - use ${ENV_VAR} instead");
        }

        // 2. TLS disabled / insecure trust manager.
        if (key.equals("server.ssl.enabled") && lower.equals("false")) {
            add(out, "insecure-transport", Severity.MEDIUM, file, line(lines, key, value),
                    "HTTPS disabled (server.ssl.enabled: false)");
        }
        if (leaf.equals("use-insecure-trust-manager") && lower.equals("true")) {
            add(out, "insecure-transport", Severity.HIGH, file, line(lines, key, value),
                    "TLS certificate validation disabled (" + key + ": true)");
        }

        // 3. Spring Security auto-configuration excluded.
        if (key.contains("autoconfigure.exclude") && value.contains("SecurityAutoConfiguration")) {
            add(out, "security-disabled", Severity.HIGH, file, line(lines, key, "SecurityAutoConfiguration"),
                    "Spring Security auto-configuration is excluded (" + key + ")");
        }

        // 4. Actuator exposure.
        if (key.equals("management.endpoints.web.exposure.include") && value.contains("*")) {
            add(out, "actuator-exposure", Severity.HIGH, file, line(lines, key, "*"),
                    "All Actuator endpoints exposed (env/heapdump/beans leak secrets and internals)");
        }
        if (key.equals("management.endpoint.health.show-details") && lower.equals("always")) {
            add(out, "actuator-exposure", Severity.LOW, file, line(lines, key, value),
                    "Actuator health details always shown (may leak DB / component info)");
        }

        // 5. H2 console enabled (especially exposed to other hosts).
        if (key.equals("spring.h2.console.enabled") && lower.equals("true")) {
            add(out, "h2-console-enabled", Severity.MEDIUM, file, line(lines, "spring.h2.console.enabled", value),
                    "H2 console enabled (often left on in production)");
        }
        if (leaf.equals("web-allow-others") && lower.equals("true")) {
            add(out, "h2-console-enabled", Severity.HIGH, file, line(lines, key, value),
                    "H2 console reachable from any host (" + key + ": true)");
        }
    }

    /** A value that is a real literal, not an externalized reference, boolean or number. */
    private static boolean isLiteralSecret(String value) {
        String v = value.strip();
        if (v.isEmpty() || v.contains("${") || v.startsWith("@") || v.startsWith("#{")) {
            return false;
        }
        if (v.equalsIgnoreCase("true") || v.equalsIgnoreCase("false")) {
            return false;
        }
        return !v.matches("-?\\d+(\\.\\d+)?");
    }

    // ---- parsing -------------------------------------------------------------

    private static Map<String, String> flattenYaml(Path file) throws IOException {
        Map<String, String> flat = new LinkedHashMap<>();
        JsonNode root = YAML.readTree(file.toFile());
        if (root != null && !root.isMissingNode()) {
            flatten("", root, flat);
        }
        return flat;
    }

    private static void flatten(String prefix, JsonNode node, Map<String, String> out) {
        if (node.isObject()) {
            for (Iterator<Map.Entry<String, JsonNode>> it = node.fields(); it.hasNext(); ) {
                Map.Entry<String, JsonNode> e = it.next();
                flatten(prefix.isEmpty() ? e.getKey() : prefix + "." + e.getKey(), e.getValue(), out);
            }
        } else if (node.isArray()) {
            // Join scalar list elements (e.g. autoconfigure.exclude, exposure.include).
            StringBuilder joined = new StringBuilder();
            for (int i = 0; i < node.size(); i++) {
                JsonNode el = node.get(i);
                if (el.isValueNode()) {
                    if (joined.length() > 0) {
                        joined.append(',');
                    }
                    joined.append(el.asText());
                } else {
                    flatten(prefix + "[" + i + "]", el, out);
                }
            }
            if (joined.length() > 0) {
                out.put(prefix, joined.toString());
            }
        } else if (node.isValueNode()) {
            out.put(prefix, node.asText());
        }
    }

    private static Map<String, String> parseProperties(List<String> lines) {
        Map<String, String> flat = new LinkedHashMap<>();
        for (String raw : lines) {
            String line = raw.strip();
            if (line.isEmpty() || line.startsWith("#") || line.startsWith("!")) {
                continue;
            }
            int sep = indexOfSeparator(line);
            if (sep > 0) {
                flat.put(line.substring(0, sep).strip(), line.substring(sep + 1).strip());
            }
        }
        return flat;
    }

    private static int indexOfSeparator(String line) {
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == '=' || c == ':') {
                return i;
            }
        }
        return -1;
    }

    /**
     * Best-effort 1-based line of a dotted key. Prefers a line carrying both the
     * leaf segment and the value (disambiguates generic leaves such as
     * {@code enabled} that appear several times); falls back to the leaf alone.
     */
    private static int line(List<String> lines, String key, String value) {
        String leaf = key.substring(key.lastIndexOf('.') + 1);
        Pattern leafOnly = Pattern.compile("(^|[\\s.])" + Pattern.quote(leaf) + "\\s*[:=]");
        Pattern withValue = Pattern.compile(
                "(^|[\\s.])" + Pattern.quote(leaf) + "\\s*[:=].*" + Pattern.quote(value.strip()));
        int fallback = 0;
        for (int i = 0; i < lines.size(); i++) {
            String l = lines.get(i);
            if (!value.isBlank() && withValue.matcher(l).find()) {
                return i + 1;
            }
            if (fallback == 0 && leafOnly.matcher(l).find()) {
                fallback = i + 1;
            }
        }
        return fallback;
    }

    private static void add(List<Finding> out, String rule, Severity sev, String file, int line, String msg) {
        out.add(new Finding(rule, sev, msg, null, file, line,
                List.of(new FlowStep(file, line, msg))));
    }

    private static String mask(String s) {
        String t = s.strip();
        return t.length() <= 4 ? "***" : t.substring(0, 3) + "***";
    }
}
