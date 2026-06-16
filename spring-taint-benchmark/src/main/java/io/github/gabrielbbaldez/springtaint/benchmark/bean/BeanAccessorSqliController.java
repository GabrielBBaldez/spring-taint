package io.github.gabrielbbaldez.springtaint.benchmark.bean;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * SQL injection where the tainted value round-trips through a value object: it is set
 * on a bean and later read back via the getter, then concatenated into SQL. This is
 * how request data usually moves in real apps (DTOs / form beans), and it is missed
 * unless beans are modelled as taint containers.
 *
 * <p>EXPECTED: sql-injection (CWE-89). Source: @RequestParam via a bean setter/getter.
 */
@RestController
public class BeanAccessorSqliController {

    private final JdbcTemplate jdbc;

    public BeanAccessorSqliController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @GetMapping("/bean-search")
    public int search(@RequestParam String term) {                        // taint-source: @RequestParam term
        SearchForm form = new SearchForm();
        form.setTerm(term);                                               // setter taints the bean
        String value = form.getTerm();                                    // getter reads the tainted value back
        return jdbc.update("SELECT * FROM items WHERE term = '" + value + "'"); // taint-sink -> EXPECTED sql-injection
    }
}
