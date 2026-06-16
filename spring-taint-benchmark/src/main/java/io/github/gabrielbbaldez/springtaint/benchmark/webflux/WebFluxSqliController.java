package io.github.gabrielbbaldez.springtaint.benchmark.webflux;

import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;

import java.util.Map;

/**
 * SQL injection in reactive (WebFlux / R2DBC) code: the tainted query is
 * concatenated into SQL and executed through {@link DatabaseClient}.
 *
 * <p>EXPECTED: sql-injection (CWE-89).
 */
@RestController
public class WebFluxSqliController {

    private final DatabaseClient databaseClient;

    public WebFluxSqliController(DatabaseClient databaseClient) {
        this.databaseClient = databaseClient;
    }

    @GetMapping("/products/search")
    public Flux<Map<String, Object>> search(@RequestParam String query) {           // taint-source: @RequestParam query
        String sql = "SELECT * FROM products WHERE name LIKE '%" + query + "%'";    // tainted concatenation
        return databaseClient.sql(sql).fetch().all();                              // taint-sink: DatabaseClient.sql -> EXPECTED sql-injection
    }
}
