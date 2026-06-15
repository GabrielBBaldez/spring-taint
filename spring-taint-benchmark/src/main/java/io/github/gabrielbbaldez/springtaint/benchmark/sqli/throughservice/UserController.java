package io.github.gabrielbbaldez.springtaint.benchmark.sqli.throughservice;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Interprocedural SQL injection: the tainted value crosses three layers
 * (Controller -> Service -> Repository) before reaching the SQL sink.
 *
 * <p>This is the flagship case: a same-function analyzer cannot see it.
 *
 * <p>EXPECTED: sql-injection (CWE-89), cross-layer.
 */
@RestController
public class UserController {

    private final UserService service;

    public UserController(UserService service) {
        this.service = service;
    }

    @GetMapping("/users/search")
    public List<User> search(@RequestParam String name) { // taint-source: @RequestParam name
        return service.search(name);                      // flows Controller -> Service -> Repository -> SQL
    }
}
