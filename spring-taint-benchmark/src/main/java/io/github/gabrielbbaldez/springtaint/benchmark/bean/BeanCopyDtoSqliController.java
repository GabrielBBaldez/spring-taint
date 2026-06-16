package io.github.gabrielbbaldez.springtaint.benchmark.bean;

import org.springframework.beans.BeanUtils;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * SQL injection where the tainted request DTO is copied into a persistence entity
 * through Spring's reflection-based BeanUtils.copyProperties (the canonical
 * service-layer DTO-to-entity mapping), then read from the entity into the query.
 * The bean-copy transfer carries the taint across the reflective copy, which the
 * analysis cannot otherwise observe.
 *
 * <p>EXPECTED: sql-injection (CWE-89).
 */
@RestController
public class BeanCopyDtoSqliController {

    /** Inbound request DTO. */
    public static final class SearchRequest {
        private String term;

        public String getTerm() {
            return term;
        }

        public void setTerm(String term) {
            this.term = term;
        }
    }

    /** Persistence entity the request is copied into. */
    public static final class SearchEntity {
        private String term;

        public String getTerm() {
            return term;
        }

        public void setTerm(String term) {
            this.term = term;
        }
    }

    private final JdbcTemplate jdbc;

    public BeanCopyDtoSqliController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @PostMapping("/by-copy")
    public void run(@RequestBody SearchRequest req) {                              // taint-source: @RequestBody
        SearchEntity entity = new SearchEntity();
        BeanUtils.copyProperties(req, entity);                                     // reflective copy carries taint req -> entity
        jdbc.execute("SELECT * FROM items WHERE term = '" + entity.getTerm() + "'"); // taint-sink: JdbcTemplate.execute -> EXPECTED sql-injection
    }
}
