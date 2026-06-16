package io.github.gabrielbbaldez.springtaint.benchmark.misconfig;

import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Over-permissive CORS: any origin may make cross-origin requests. Combined with
 * credentialed requests this is especially dangerous.
 *
 * <p>EXPECTED: insecure-config (CORS origins "*").
 */
@RestController
@CrossOrigin(origins = "*")
public class PermissiveCorsController {

    @GetMapping("/cors/data")
    public String data() {
        return "data";
    }
}
