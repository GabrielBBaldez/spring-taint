package io.github.gabrielbbaldez.springtaint.benchmark.bean;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * SQL injection through the builder pattern (the Lombok @Builder shape, written by hand
 * here). The taint enters a builder setter, survives build(), and exits via the built
 * object's getter -- a chain the bean model must follow end to end.
 *
 * <p>EXPECTED: sql-injection (CWE-89).
 */
@RestController
public class BuilderDtoSqliController {

    /** A value object built via a fluent builder (mirrors Lombok @Builder). */
    public static final class Query {
        private final String term;

        private Query(Builder b) {
            this.term = b.term;
        }

        public String getTerm() {
            return term;
        }

        public static Builder builder() {
            return new Builder();
        }

        public static final class Builder {
            private String term;

            public Builder term(String term) {   // builder setter: field-named, returns the builder
                this.term = term;
                return this;
            }

            public Query build() {               // builder terminal
                return new Query(this);
            }
        }
    }

    private final JdbcTemplate jdbc;

    public BuilderDtoSqliController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @PostMapping("/by-builder")
    public void run(@RequestParam String term) {                                // taint-source: @RequestParam
        Query q = Query.builder().term(term).build();                           // builder chain carries the taint
        jdbc.execute("SELECT * FROM items WHERE term = '" + q.getTerm() + "'");  // taint-sink: JdbcTemplate.execute -> EXPECTED sql-injection
    }
}
