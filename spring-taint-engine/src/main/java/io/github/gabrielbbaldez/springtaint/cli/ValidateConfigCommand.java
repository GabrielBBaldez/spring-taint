package io.github.gabrielbbaldez.springtaint.cli;

import io.github.gabrielbbaldez.springtaint.config.ConfigValidator;
import io.github.gabrielbbaldez.springtaint.config.ConfigValidator.Issue;
import io.github.gabrielbbaldez.springtaint.config.ConfigValidator.Report;
import io.github.gabrielbbaldez.springtaint.config.TaintConfig;
import io.github.gabrielbbaldez.springtaint.config.TaintConfigLoader;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.InputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;

/**
 * {@code spring-taint validate-config [CONFIG] --classpath CP} — resolves the
 * method signatures in a taint config against a classpath, so a typo (which would
 * silently match nothing) is reported before a scan gives false confidence.
 */
@Command(
        name = "validate-config",
        description = "Resolve a taint config's method signatures against a classpath.")
public final class ValidateConfigCommand implements Callable<Integer> {

    @Parameters(index = "0", arity = "0..1", paramLabel = "CONFIG",
            description = "Taint config YAML to validate (default: the bundled config).")
    private Path config;

    @Option(names = {"-l", "--classpath", "--libs"}, paramLabel = "CLASSPATH",
            description = "Classpath to resolve signatures against (path-separator-joined "
                    + "jars/dirs). The JDK is always available.")
    private String classpath;

    @Override
    public Integer call() throws Exception {
        TaintConfig cfg = loadConfig();
        if (cfg == null) {
            return 2;
        }
        Report report = new ConfigValidator().validate(cfg, classpathUrls());

        System.out.printf("%d of %d signature(s) resolved.%n", report.resolved(), report.total());
        for (Issue issue : report.issues()) {
            System.out.printf("  [unresolved] %s%n               %s%n", issue.signature(), issue.reason());
        }
        if (report.ok()) {
            System.out.println("All signatures resolved against the classpath.");
        } else {
            System.out.println("Unresolved signatures never match; verify the signature "
                    + "or add the missing jar to --classpath.");
        }
        return report.ok() ? 0 : 1;
    }

    private TaintConfig loadConfig() throws Exception {
        if (config != null) {
            if (!Files.exists(config)) {
                System.err.println("Config not found: " + config);
                return null;
            }
            return TaintConfigLoader.load(config);
        }
        try (InputStream bundled = getClass().getResourceAsStream("/spring-taint.yml")) {
            if (bundled == null) {
                System.err.println("No config given and no bundled default found.");
                return null;
            }
            return TaintConfigLoader.load(bundled);
        }
    }

    private List<URL> classpathUrls() throws Exception {
        List<URL> urls = new ArrayList<>();
        if (classpath == null || classpath.isBlank()) {
            return urls;
        }
        for (String entry : classpath.split(java.io.File.pathSeparator)) {
            if (!entry.isBlank()) {
                urls.add(Path.of(entry.trim()).toUri().toURL());
            }
        }
        return urls;
    }
}
