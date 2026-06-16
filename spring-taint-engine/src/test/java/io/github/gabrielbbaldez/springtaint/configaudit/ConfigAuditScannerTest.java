package io.github.gabrielbbaldez.springtaint.configaudit;

import io.github.gabrielbbaldez.springtaint.report.Finding;
import io.github.gabrielbbaldez.springtaint.testutil.Fixtures;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertTrue;

class ConfigAuditScannerTest {

    @Test
    void flagsInsecureSettings(@TempDir Path dir) throws Exception {
        Fixtures.write(dir, "application-insecure.yml", """
                spring:
                  datasource:
                    password: admin123
                  autoconfigure:
                    exclude: org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration
                  h2:
                    console:
                      enabled: true
                server:
                  ssl:
                    enabled: false
                management:
                  endpoints:
                    web:
                      exposure:
                        include: "*"
                """);
        Set<String> rules = new ConfigAuditScanner().scan(dir).stream()
                .map(Finding::ruleId).collect(Collectors.toSet());
        assertTrue(rules.contains("hardcoded-secret"), rules.toString());
        assertTrue(rules.contains("security-disabled"), rules.toString());
        assertTrue(rules.contains("h2-console-enabled"), rules.toString());
        assertTrue(rules.contains("insecure-transport"), rules.toString());
        assertTrue(rules.contains("actuator-exposure"), rules.toString());
    }

    @Test
    void allowsSafeSettings(@TempDir Path dir) throws Exception {
        Fixtures.write(dir, "application-safe.yml", """
                spring:
                  datasource:
                    password: ${DB_PASSWORD}
                  h2:
                    console:
                      enabled: false
                server:
                  ssl:
                    enabled: true
                management:
                  endpoints:
                    web:
                      exposure:
                        include: health,info
                """);
        List<Finding> out = new ConfigAuditScanner().scan(dir);
        assertTrue(out.isEmpty(), () -> "expected no findings, got " + out);
    }
}
