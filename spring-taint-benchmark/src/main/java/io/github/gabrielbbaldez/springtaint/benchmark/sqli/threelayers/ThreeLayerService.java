package io.github.gabrielbbaldez.springtaint.benchmark.sqli.threelayers;

import org.springframework.stereotype.Service;

import java.util.List;

/** Service layer; delegates through a validator that does not sanitize for SQL. */
@Service
public class ThreeLayerService {

    private final ThreeLayerValidator validator;
    private final ThreeLayerRepository repository;

    public ThreeLayerService(ThreeLayerValidator validator, ThreeLayerRepository repository) {
        this.validator = validator;
        this.repository = repository;
    }

    public List<String> search(String name) {
        String normalized = validator.normalize(name); // still tainted
        return repository.findByName(normalized);
    }
}
