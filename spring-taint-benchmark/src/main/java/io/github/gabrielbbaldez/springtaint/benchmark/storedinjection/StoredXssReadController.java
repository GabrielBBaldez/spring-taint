package io.github.gabrielbbaldez.springtaint.benchmark.storedinjection;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

/**
 * Request 2 of a stored-injection pair: reads persisted data and renders it
 * without escaping. The taint enters through the repository read (persistence
 * source), not through this request's parameters — a cross-request flow that
 * same-request analyzers miss.
 *
 * <p>EXPECTED: xss (CWE-79), stored / second-order.
 */
@RestController
public class StoredXssReadController {

    private final NoteRepository repository;

    public StoredXssReadController(NoteRepository repository) {
        this.repository = repository;
    }

    @GetMapping("/notes/{id}")
    public void read(@PathVariable long id, HttpServletResponse response) throws IOException {
        String text = repository.findText(id);                  // taint-source: @Repository read (stored data)
        response.getWriter().write("<p>" + text + "</p>");      // taint-sink: PrintWriter.write -> EXPECTED xss
    }
}
