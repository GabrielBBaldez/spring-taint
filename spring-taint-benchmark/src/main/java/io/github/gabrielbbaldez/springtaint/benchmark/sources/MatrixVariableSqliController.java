package io.github.gabrielbbaldez.springtaint.benchmark.sources;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.MatrixVariable;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/**
 * SQL injection from a matrix variable. Matrix variables — parameters embedded in
 * the path like {@code /users/42;role=admin} — are a rarely-modelled Spring MVC
 * source, so this flow slips past tools that only know the common annotations.
 *
 * <p>EXPECTED: sql-injection (CWE-89). Source: @MatrixVariable.
 */
@RestController
public class MatrixVariableSqliController {

    private final JdbcTemplate jdbc;

    public MatrixVariableSqliController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @GetMapping("/users/{userId}")
    public int byRole(@PathVariable String userId,
                      @MatrixVariable String role) {                    // taint-source: @MatrixVariable role
        String sql = "SELECT * FROM users WHERE role = '" + role + "'"; // tainted concatenation
        return jdbc.update(sql);                                        // taint-sink: JdbcTemplate.update -> EXPECTED sql-injection
    }
}
