package io.github.gabrielbbaldez.springtaint.benchmark.nearmiss;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Near-miss (insufficient sanitization): the developer strips single quotes and
 * believes the query is safe, but quote-stripping does not prevent SQL injection
 * (backslash escaping, alternate encodings, SQL functions). The only correct fix is
 * a parameterized query.
 *
 * <p>EXPECTED: sql-injection (CWE-89), flagged as a near-miss sanitizer.
 */
@RestController
public class NearMissSqlController {

    private final JdbcTemplate jdbc;

    public NearMissSqlController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @GetMapping("/nm/sql")
    public int search(@RequestParam String name) {                      // taint-source: @RequestParam name
        String safe = name.replaceAll("'", "");                         // near-miss: stripping quotes is not enough
        String sql = "SELECT * FROM users WHERE name = '" + safe + "'";
        return jdbc.update(sql);                                        // taint-sink -> EXPECTED sql-injection
    }
}
