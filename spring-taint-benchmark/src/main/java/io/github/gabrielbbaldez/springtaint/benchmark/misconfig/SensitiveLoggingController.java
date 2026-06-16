package io.github.gabrielbbaldez.springtaint.benchmark.misconfig;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Sensitive-data exposure in logs: a password is written to the log in clear text.
 * Anyone with log access (or a log-shipping pipeline) then sees the credential.
 *
 * <p>EXPECTED: insecure-config (sensitive data logged). The safe endpoint logs only
 * the username and must NOT be flagged.
 */
@RestController
public class SensitiveLoggingController {

    private static final Logger log = LoggerFactory.getLogger(SensitiveLoggingController.class);

    @GetMapping("/auth")
    public String auth(@RequestParam String username, @RequestParam String password) {
        log.info("Authenticating user={} password={}", username, password);   // misconfig: logs the password
        return "ok";
    }

    @GetMapping("/auth-safe")
    public String authSafe(@RequestParam String username, @RequestParam String password) {
        log.info("Authenticating user={}", username);                         // safe: only the username
        return "ok";
    }
}
