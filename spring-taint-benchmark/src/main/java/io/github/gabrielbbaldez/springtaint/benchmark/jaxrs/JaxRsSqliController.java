package io.github.gabrielbbaldez.springtaint.benchmark.jaxrs;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * SQL injection with a JAX-RS source ({@code @QueryParam}), as used by Quarkus
 * and Jakarta REST. Demonstrates that the analyzer's source layer is not
 * Spring-specific — any configured framework annotation works.
 *
 * <p>EXPECTED: sql-injection (CWE-89).
 */
@Path("/jaxrs/users")
public class JaxRsSqliController {

    private final JdbcTemplate jdbc;

    public JaxRsSqliController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @GET
    public int delete(@QueryParam("id") String id) {            // taint-source: @QueryParam (JAX-RS / Quarkus)
        return jdbc.update("DELETE FROM users WHERE id = " + id); // taint-sink: JdbcTemplate.update -> EXPECTED sql-injection
    }
}
