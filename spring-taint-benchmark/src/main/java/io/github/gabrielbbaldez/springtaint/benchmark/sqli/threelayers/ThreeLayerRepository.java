package io.github.gabrielbbaldez.springtaint.benchmark.sqli.threelayers;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

import java.util.List;

/** Repository layer; the tainted name reaches a concatenated SQL query. */
@Repository
public class ThreeLayerRepository {

    private static final RowMapper<String> NAME_MAPPER = (rs, rowNum) -> rs.getString("name");

    private final JdbcTemplate jdbc;

    public ThreeLayerRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public List<String> findByName(String name) {
        String sql = "SELECT name FROM users WHERE name = '" + name + "'"; // tainted concatenation
        return jdbc.query(sql, NAME_MAPPER);                               // taint-sink: JdbcTemplate.query -> EXPECTED sql-injection
    }
}
