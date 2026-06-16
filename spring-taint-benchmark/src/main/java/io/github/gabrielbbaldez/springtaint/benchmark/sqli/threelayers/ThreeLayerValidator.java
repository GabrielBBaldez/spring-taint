package io.github.gabrielbbaldez.springtaint.benchmark.sqli.threelayers;

import org.springframework.stereotype.Component;

/** A "validator" that normalizes whitespace but does NOT neutralize SQL. */
@Component
public class ThreeLayerValidator {

    public String normalize(String name) {
        return name.trim(); // trimming is not SQL sanitization
    }
}
