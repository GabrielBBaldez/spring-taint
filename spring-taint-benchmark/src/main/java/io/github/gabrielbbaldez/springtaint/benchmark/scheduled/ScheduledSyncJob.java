package io.github.gabrielbbaldez.springtaint.benchmark.scheduled;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * A scheduled job that reads external/persisted data and writes it to the database
 * without sanitization. {@code @Scheduled} methods take no request parameters, so
 * tools that only treat request handlers as entry points never analyse them.
 *
 * <p>EXPECTED: sql-injection (CWE-89). Entry point: @Scheduled; source: a @Repository read.
 */
@Component
public class ScheduledSyncJob {

    private final PayloadRepository repository;
    private final JdbcTemplate jdbc;

    public ScheduledSyncJob(PayloadRepository repository, JdbcTemplate jdbc) {
        this.repository = repository;
        this.jdbc = jdbc;
    }

    @Scheduled(fixedRate = 5000)
    public void sync() {                                   // taint-entry: @Scheduled (no request input)
        String data = repository.findLatestPayload();      // taint-source: @Repository read
        jdbc.execute("INSERT INTO cache(v) VALUES ('" + data + "')"); // taint-sink -> EXPECTED sql-injection
    }
}
