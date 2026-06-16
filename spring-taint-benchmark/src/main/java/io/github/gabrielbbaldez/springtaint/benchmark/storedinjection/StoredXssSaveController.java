package io.github.gabrielbbaldez.springtaint.benchmark.storedinjection;

import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Request 1 of a stored-injection pair: persists untrusted input.
 */
@RestController
public class StoredXssSaveController {

    private final NoteRepository repository;

    public StoredXssSaveController(NoteRepository repository) {
        this.repository = repository;
    }

    @PostMapping("/notes/{id}")
    public void save(@PathVariable long id, @RequestBody String note) { // taint-source: @RequestBody note
        repository.saveText(id, note);                                  // tainted data persists
    }
}
