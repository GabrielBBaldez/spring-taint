package io.github.gabrielbbaldez.springtaint.report.sarif;

import io.github.gabrielbbaldez.springtaint.report.Finding;
import io.github.gabrielbbaldez.springtaint.report.FlowStep;
import io.github.gabrielbbaldez.springtaint.report.Severity;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

class SarifWriterTest {

    @Test
    void producesSarifWithResultAndCodeFlow() {
        Finding f = new Finding(
                "sql-injection",
                Severity.CRITICAL,
                "Tainted @RequestParam reaches JdbcTemplate.query",
                "GET /users/search",
                "UserRepository.java",
                34,
                List.of(
                        new FlowStep("UserController.java", 12, "@RequestParam String name"),
                        new FlowStep("UserService.java", 20, "search(name)"),
                        new FlowStep("UserRepository.java", 34, "JdbcTemplate.query(sql)")));

        String json = new SarifWriter().toJson(List.of(f));

        assertTrue(json.contains("2.1.0"), json);
        assertTrue(json.contains("\"version\""), json);
        assertTrue(json.contains("sql-injection"), json);
        assertTrue(json.contains("codeFlows"), json);
        assertTrue(json.contains("error"), json);
        assertTrue(json.contains("UserController.java"), json);
    }

    @Test
    void emptyFindingsStillValidDocument() {
        String json = new SarifWriter().toJson(List.of());

        assertTrue(json.contains("2.1.0"), json);
        assertTrue(json.contains("\"results\""), json);
    }
}
