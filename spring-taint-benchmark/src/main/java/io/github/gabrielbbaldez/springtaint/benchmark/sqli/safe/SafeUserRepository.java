package io.github.gabrielbbaldez.springtaint.benchmark.sqli.safe;

import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * SAFE counterpart of the through-service case. The user value is bound as a
 * query parameter via {@link NamedParameterJdbcTemplate}, never concatenated
 * into SQL text, so it is not exploitable.
 *
 * <p>EXPECTED: safe — this flow must NOT be flagged (measures precision).
 */
@Repository
public class SafeUserRepository {

    private static final RowMapper<String> NAME_MAPPER = (rs, rowNum) -> rs.getString("name");

    private final NamedParameterJdbcTemplate jdbc;

    public SafeUserRepository(NamedParameterJdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public List<String> findByName(String name) {
        String sql = "SELECT name FROM users WHERE name = :name";       // parameterized, not concatenated
        MapSqlParameterSource params = new MapSqlParameterSource("name", name);
        return jdbc.query(sql, params, NAME_MAPPER);                    // bound parameter -> EXPECTED safe
    }
}
