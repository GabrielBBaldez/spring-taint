package io.github.gabrielbbaldez.springtaint.benchmark.sqli.safe;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * SAFE: the user value is passed as a bound {@code ?} parameter to a
 * parameterized query, never concatenated into the SQL text.
 *
 * <p>EXPECTED: safe — must NOT be flagged (measures precision).
 */
@RestController
public class PreparedStatementController {

    private static final RowMapper<String> NAME_MAPPER = (rs, rowNum) -> rs.getString("name");

    private final JdbcTemplate jdbc;

    public PreparedStatementController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @GetMapping("/users/search-prepared")
    public List<String> search(@RequestParam String name) {                  // taint-source: @RequestParam name
        return jdbc.query("SELECT name FROM users WHERE name = ?",
                new Object[]{name}, NAME_MAPPER);                            // bound parameter -> EXPECTED safe
    }
}
