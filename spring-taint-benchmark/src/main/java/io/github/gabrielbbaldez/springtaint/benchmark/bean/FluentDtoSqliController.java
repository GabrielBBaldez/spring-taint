package io.github.gabrielbbaldez.springtaint.benchmark.bean;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * SQL injection through a fluent setter (the Lombok @Accessors(fluent = true) shape): the
 * setter is named after the field, takes the value and returns the bean for chaining.
 *
 * <p>EXPECTED: sql-injection (CWE-89).
 */
@RestController
public class FluentDtoSqliController {

    /** A command object with a fluent setter (mirrors Lombok @Accessors(fluent = true)). */
    public static final class Filter {
        private String term;

        public Filter term(String term) {   // fluent setter: field-named, returns the bean
            this.term = term;
            return this;
        }

        public String getTerm() {
            return term;
        }
    }

    private final JdbcTemplate jdbc;

    public FluentDtoSqliController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @PostMapping("/by-fluent")
    public void run(@RequestParam String term) {                                // taint-source: @RequestParam
        Filter f = new Filter().term(term);                                     // fluent setter chains the taint
        jdbc.execute("SELECT * FROM items WHERE term = '" + f.getTerm() + "'");  // taint-sink: JdbcTemplate.execute -> EXPECTED sql-injection
    }
}
