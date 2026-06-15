package io.github.gabrielbbaldez.springtaint.benchmark.sqli.throughservice;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * Repository layer. The tainted name reaches a concatenated SQL query here, two
 * call hops away from the controller that received it.
 */
@Repository
public class UserRepository {

    private static final RowMapper<User> MAPPER =
            (rs, rowNum) -> new User(rs.getLong("id"), rs.getString("name"));

    private final JdbcTemplate jdbc;

    public UserRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public List<User> findByName(String name) {
        String sql = "SELECT id, name FROM users WHERE name = '" + name + "'"; // tainted concatenation
        return jdbc.query(sql, MAPPER);                                        // taint-sink: JdbcTemplate.query -> EXPECTED sql-injection
    }
}
