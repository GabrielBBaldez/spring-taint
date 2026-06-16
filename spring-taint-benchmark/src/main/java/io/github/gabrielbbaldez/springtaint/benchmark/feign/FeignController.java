package io.github.gabrielbbaldez.springtaint.benchmark.feign;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * SQL injection where the tainted value comes from a downstream microservice via a
 * {@code @FeignClient}, not from the immediate HTTP request — a cross-service flow
 * that tools treating Feign results as trusted will miss.
 *
 * <p>EXPECTED: sql-injection (CWE-89). Source: the @FeignClient method's result.
 */
@RestController
public class FeignController {

    private final UserClient userClient;
    private final JdbcTemplate jdbc;

    public FeignController(UserClient userClient, JdbcTemplate jdbc) {
        this.userClient = userClient;
        this.jdbc = jdbc;
    }

    @GetMapping("/feign/lookup")
    public int lookup(@RequestParam String id) {
        String name = userClient.getUserName(id);    // taint-source: @FeignClient result (downstream service)
        return jdbc.update("DELETE FROM users WHERE name = '" + name + "'"); // taint-sink -> EXPECTED sql-injection
    }
}
