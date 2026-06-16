package io.github.gabrielbbaldez.springtaint.benchmark.transactional;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Stored injection inside a single {@code @Transactional} method: untrusted input is
 * persisted, then read back (Hibernate may serve it from the first-level cache) and
 * reaches a sink while still tainted.
 *
 * <p>EXPECTED: sql-injection (CWE-89). The read-back is a @Repository source.
 */
@RestController
public class TransactionalController {

    private final JournalRepository repository;
    private final JdbcTemplate jdbc;

    public TransactionalController(JournalRepository repository, JdbcTemplate jdbc) {
        this.repository = repository;
        this.jdbc = jdbc;
    }

    @PostMapping("/journal")
    @Transactional
    public int post(@RequestBody String entry) {
        repository.save(entry);
        String stored = repository.findLatest();           // taint-source: @Repository read (same transaction)
        return jdbc.update("UPDATE journal SET v = '" + stored + "' WHERE id = 1"); // taint-sink -> EXPECTED sql-injection
    }
}
