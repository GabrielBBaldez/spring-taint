package io.github.gabrielbbaldez.springtaint.benchmark.sources;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/**
 * SQL injection where the source is a {@code @PathVariable}.
 *
 * <p>EXPECTED: sql-injection (CWE-89).
 */
@RestController
public class PathVariableSqliController {

    private final JdbcTemplate jdbc;

    public PathVariableSqliController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @GetMapping("/users/{id}/delete")
    public int delete(@PathVariable String id) {                 // taint-source: @PathVariable id
        return jdbc.update("DELETE FROM users WHERE id = " + id); // taint-sink: JdbcTemplate.update -> EXPECTED sql-injection
    }
}
