package io.github.gabrielbbaldez.springtaint.secrets;

import io.github.gabrielbbaldez.springtaint.report.Finding;
import io.github.gabrielbbaldez.springtaint.report.Severity;
import io.github.gabrielbbaldez.springtaint.testutil.Fixtures;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

class SecretScannerTest {

    @Test
    void detectsSecretNamedConstantsAndKnownFormats(@TempDir Path dir) throws Exception {
        Path classes = Fixtures.compile(dir, "p.Secrets", """
                package p;
                class Secrets {
                    static final String PASSWORD = "hunter2-literal-pw";
                    static final String AWS = "AKIAIOSFODNN7EXAMPLE";
                }
                """);
        List<Finding> out = new SecretScanner().scan(classes);

        assertTrue(out.stream().anyMatch(f -> f.message().contains("PASSWORD")),
                () -> "secret-named constant not flagged: " + out);
        assertTrue(out.stream().anyMatch(f -> f.severity() == Severity.CRITICAL),
                () -> "AWS key format not flagged as critical: " + out);
        assertTrue(out.stream().allMatch(f -> !f.message().contains("hunter2-literal-pw")
                && !f.message().contains("AKIAIOSFODNN7EXAMPLE")), "values must be masked");
    }
}
