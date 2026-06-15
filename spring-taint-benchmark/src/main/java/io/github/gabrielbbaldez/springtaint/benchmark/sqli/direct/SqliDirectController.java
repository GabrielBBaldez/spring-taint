package io.github.gabrielbbaldez.springtaint.benchmark.sqli.direct;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * SQL injection where the source and the sink live in the SAME method.
 *
 * <p>Baseline case: even a same-function analyzer (e.g. SonarQube) detects this.
 * It exists to confirm the analyzer does not miss the easy case.
 *
 * <p>EXPECTED: sql-injection (CWE-89).
 */
@RestController
public class SqliDirectController {

    private final JdbcTemplate jdbc;

    public SqliDirectController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @GetMapping("/sqli/direct")
    public int delete(@RequestParam String id) {            // taint-source: @RequestParam id
        String sql = "DELETE FROM users WHERE id = " + id;  // tainted string concatenation
        return jdbc.update(sql);                            // taint-sink: JdbcTemplate.update -> EXPECTED sql-injection
    }
}
