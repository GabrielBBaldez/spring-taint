package io.github.gabrielbbaldez.springtaint.benchmark.sources;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * SQL injection where the source is a Map-typed request binding. Spring binds all
 * query parameters into a {@code @RequestParam Map}, so values read out of it with
 * {@code get(...)} are attacker-controlled — a common real-world pattern.
 *
 * <p>EXPECTED: sql-injection (CWE-89). Source: @RequestParam Map, value via Map.get.
 */
@RestController
public class MapParamSqliController {

    private final JdbcTemplate jdbc;

    public MapParamSqliController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @GetMapping("/map-search")
    public int search(@RequestParam Map<String, String> params) {              // taint-source: @RequestParam Map
        String name = params.get("name");                                      // tainted value via Map.get
        return jdbc.update("SELECT * FROM users WHERE name = '" + name + "'");  // taint-sink -> EXPECTED sql-injection
    }
}
