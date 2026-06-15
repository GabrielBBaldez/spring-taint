package io.github.gabrielbbaldez.springtaint.benchmark.pathtraversal.direct;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

/**
 * Path traversal: an untrusted filename is concatenated into a filesystem path.
 * A payload such as {@code ../../etc/passwd} escapes the intended directory.
 *
 * <p>EXPECTED: path-traversal (CWE-22).
 */
@RestController
public class PathTraversalController {

    @GetMapping("/download")
    public byte[] download(@RequestParam String filename) throws IOException { // taint-source: @RequestParam filename
        File file = new File("/var/data/" + filename);                         // taint-sink: new File(String) -> EXPECTED path-traversal
        return Files.readAllBytes(file.toPath());
    }
}
