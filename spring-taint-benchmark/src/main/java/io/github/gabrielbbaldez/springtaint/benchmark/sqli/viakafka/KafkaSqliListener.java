package io.github.gabrielbbaldez.springtaint.benchmark.sqli.viakafka;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

/**
 * SQL injection whose source is a Kafka message, not an HTTP request. The
 * {@code @KafkaListener} payload is external, untrusted input with no explicit
 * call site — a vector ignored by existing open-source taint tools.
 *
 * <p>EXPECTED: sql-injection (CWE-89). Source modelling is a Phase 2 target.
 */
@Component
public class KafkaSqliListener {

    private final JdbcTemplate jdbc;

    public KafkaSqliListener(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @KafkaListener(topics = "user-events")
    public void onMessage(String payload) {                         // taint-source: @KafkaListener payload
        String sql = "SELECT * FROM users WHERE id = " + payload;   // tainted concatenation
        jdbc.execute(sql);                                          // taint-sink: JdbcTemplate.execute -> EXPECTED sql-injection
    }
}
