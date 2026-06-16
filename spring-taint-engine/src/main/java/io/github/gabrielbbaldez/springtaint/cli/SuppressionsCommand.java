package io.github.gabrielbbaldez.springtaint.cli;

import io.github.gabrielbbaldez.springtaint.suppress.SuppressionScanner;
import io.github.gabrielbbaldez.springtaint.suppress.SuppressionScanner.Suppression;
import picocli.CommandLine.Command;
import picocli.CommandLine.Parameters;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.Callable;

/**
 * {@code spring-taint suppressions SRC} — lists every inline
 * {@code // spring-taint: suppress RULE - reason} directive in a source tree, so
 * suppressions can be audited (each silenced finding stays documented in code).
 */
@Command(
        name = "suppressions",
        description = "List all inline '// spring-taint: suppress' directives in a source tree.")
public final class SuppressionsCommand implements Callable<Integer> {

    @Parameters(index = "0", paramLabel = "SRC",
            description = "Source file or directory to scan for suppression comments.")
    private Path src;

    @Override
    public Integer call() throws Exception {
        if (src == null || !Files.exists(src)) {
            System.err.println("Source not found: " + src);
            return 2;
        }
        List<Suppression> suppressions = new SuppressionScanner().scan(src);
        if (suppressions.isEmpty()) {
            System.out.println("No suppression directives found.");
            return 0;
        }
        for (Suppression s : suppressions) {
            System.out.printf("%s:%d  %s  %s%n", s.file(), s.line(), s.rule(),
                    s.reason().isEmpty() ? "(no reason given)" : s.reason());
        }
        System.out.printf("%d suppression(s).%n", suppressions.size());
        return 0;
    }
}
