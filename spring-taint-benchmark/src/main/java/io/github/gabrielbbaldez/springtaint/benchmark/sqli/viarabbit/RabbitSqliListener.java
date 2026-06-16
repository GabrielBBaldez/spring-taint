package io.github.gabrielbbaldez.springtaint.benchmark.sqli.viarabbit;

import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/**
 * SQL injection whose source is a RabbitMQ message. The {@code @RabbitListener}
 * payload is external, untrusted input with no explicit call site: the same
 * messaging-source vector as Kafka, on the other dominant Spring broker.
 *
 * <p>EXPECTED: sql-injection (CWE-89). Messaging sources are a Phase 2 target.
 */
@Component
public class RabbitSqliListener {

    private final JdbcTemplate jdbc;

    public RabbitSqliListener(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @RabbitListener(queues = "user-events")
    public void onMessage(String payload) {                         // taint-source: @RabbitListener payload
        String sql = "SELECT * FROM users WHERE id = " + payload;   // tainted concatenation
        jdbc.execute(sql);                                          // taint-sink: JdbcTemplate.execute -> EXPECTED sql-injection
    }
}
