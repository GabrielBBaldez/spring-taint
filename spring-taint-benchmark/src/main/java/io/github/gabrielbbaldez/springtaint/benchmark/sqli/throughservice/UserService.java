package io.github.gabrielbbaldez.springtaint.benchmark.sqli.throughservice;

import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Service layer. {@link #nameFilter(String)} looks like sanitization but does
 * not neutralise SQL metacharacters, so the taint survives.
 */
@Service
public class UserService {

    private final UserRepository repo;

    public UserService(UserRepository repo) {
        this.repo = repo;
    }

    public List<User> search(String name) {
        String filtered = nameFilter(name); // looks like sanitization, but is not
        return repo.findByName(filtered);
    }

    private String nameFilter(String name) {
        return name.trim(); // trimming does NOT sanitize for SQL
    }
}
