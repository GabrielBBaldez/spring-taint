package io.github.gabrielbbaldez.springtaint.benchmark.storedinjection;

import org.springframework.stereotype.Repository;

import java.util.HashMap;
import java.util.Map;

/**
 * A persistence repository. Text saved by one request is read back by another;
 * the analyzer treats {@code findText} (a {@code @Repository} read) as untrusted,
 * modelling stored / second-order injection.
 */
@Repository
public class NoteRepository {

    private final Map<Long, String> store = new HashMap<>();

    public void saveText(long id, String text) {
        store.put(id, text);
    }

    public String findText(long id) {
        return store.get(id);
    }
}
