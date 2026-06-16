package io.github.gabrielbbaldez.springtaint.benchmark.bean;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * SQL injection carried by a Java record's accessor. A record accessor (term()) is named
 * after its component, not with a get/is prefix, so it is modelled as a taint container
 * via the field-name match rather than the bean-getter convention.
 *
 * <p>EXPECTED: sql-injection (CWE-89). The @RequestBody record is untrusted input; its
 * accessor returns the tainted component, which is concatenated into the query.
 */
@RestController
public class RecordDtoSqliController {

    /** A request DTO as a record -- the modern Spring form/command bean. */
    public record SearchForm(String term) {
    }

    private final JdbcTemplate jdbc;

    public RecordDtoSqliController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @PostMapping("/search")
    public void search(@RequestBody SearchForm form) {                          // taint-source: @RequestBody record
        String sql = "SELECT * FROM items WHERE term = '" + form.term() + "'";   // record accessor carries the taint
        jdbc.execute(sql);                                                      // taint-sink: JdbcTemplate.execute -> EXPECTED sql-injection
    }
}
