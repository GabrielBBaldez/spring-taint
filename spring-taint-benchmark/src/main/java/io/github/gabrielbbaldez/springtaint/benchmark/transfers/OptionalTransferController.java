package io.github.gabrielbbaldez.springtaint.benchmark.transfers;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

/**
 * Taint flowing through {@link Optional}. Wrapping a tainted value in an Optional
 * and reading it back out must preserve taint — Optional is a transparent wrapper,
 * not a sanitizer.
 *
 * <p>EXPECTED: sql-injection (CWE-89). Exercises the Optional.of / get transfers.
 */
@RestController
public class OptionalTransferController {

    private final JdbcTemplate jdbc;

    public OptionalTransferController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @GetMapping("/opt")
    public int run(@RequestParam String id) {                              // taint-source: @RequestParam id
        Optional<String> wrapped = Optional.of(id);                        // taint flows into the Optional
        String unwrapped = wrapped.get();                                  // ...and back out (Object cast to String)
        return jdbc.update("DELETE FROM users WHERE id = " + unwrapped);    // taint-sink: JdbcTemplate.update -> EXPECTED sql-injection
    }
}
