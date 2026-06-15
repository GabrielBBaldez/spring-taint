package io.github.gabrielbbaldez.springtaint.benchmark.sqli.safe;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Entry point for the SAFE SQL case. A real source ({@code @RequestParam})
 * flows into the repository, but the repository binds it as a parameter, so the
 * analyzer should report nothing.
 *
 * <p>EXPECTED: safe.
 */
@RestController
public class SafeUserController {

    private final SafeUserRepository repo;

    public SafeUserController(SafeUserRepository repo) {
        this.repo = repo;
    }

    @GetMapping("/users/search-safe")
    public List<String> search(@RequestParam String name) { // taint-source: @RequestParam name
        return repo.findByName(name);                       // bound as parameter downstream -> EXPECTED safe
    }
}
