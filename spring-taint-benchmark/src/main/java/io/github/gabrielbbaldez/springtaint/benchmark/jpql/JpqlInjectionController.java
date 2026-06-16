package io.github.gabrielbbaldez.springtaint.benchmark.jpql;

import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * JPQL injection: developers often assume JPA is immune to injection, but a JPQL
 * query built by string concatenation is just as vulnerable as raw SQL. The taint
 * reaches {@code EntityManager.createQuery} rather than a JDBC method.
 *
 * <p>EXPECTED: jpql-injection (CWE-89).
 */
@RestController
public class JpqlInjectionController {

    private final EntityManager em;

    public JpqlInjectionController(EntityManager em) {
        this.em = em;
    }

    @GetMapping("/jpa/users")
    public List<?> search(@RequestParam String name) {                      // taint-source: @RequestParam name
        String jpql = "SELECT u FROM User u WHERE u.name = '" + name + "'";  // tainted JPQL concatenation
        Query query = em.createQuery(jpql);                                 // taint-sink: EntityManager.createQuery -> EXPECTED jpql-injection
        return query.getResultList();
    }
}
