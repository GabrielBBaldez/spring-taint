package io.github.gabrielbbaldez.springtaint.benchmark.sources;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * SQL injection where the source is a {@code @RequestBody}.
 *
 * <p>EXPECTED: sql-injection (CWE-89).
 */
@RestController
public class RequestBodySqliController {

    private final JdbcTemplate jdbc;

    public RequestBodySqliController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @PostMapping("/users/raw")
    public int create(@RequestBody String name) {                              // taint-source: @RequestBody name
        return jdbc.update("INSERT INTO users(name) VALUES('" + name + "')");  // taint-sink: JdbcTemplate.update -> EXPECTED sql-injection
    }
}
