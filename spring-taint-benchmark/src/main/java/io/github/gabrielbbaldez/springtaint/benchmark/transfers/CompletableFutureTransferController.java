package io.github.gabrielbbaldez.springtaint.benchmark.transfers;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

/**
 * Taint flowing through {@link CompletableFuture}. A tainted value completed into
 * a future and read back with {@code get()} must remain tainted across the async
 * boundary.
 *
 * <p>EXPECTED: sql-injection (CWE-89). Exercises the CompletableFuture transfers.
 */
@RestController
public class CompletableFutureTransferController {

    private final JdbcTemplate jdbc;

    public CompletableFutureTransferController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @GetMapping("/async")
    public int run(@RequestParam String id) throws ExecutionException, InterruptedException { // taint-source: @RequestParam id
        CompletableFuture<String> future = CompletableFuture.completedFuture(id);
        String result = future.get();
        return jdbc.update("DELETE FROM users WHERE id = " + result);   // taint-sink: JdbcTemplate.update -> EXPECTED sql-injection
    }
}
