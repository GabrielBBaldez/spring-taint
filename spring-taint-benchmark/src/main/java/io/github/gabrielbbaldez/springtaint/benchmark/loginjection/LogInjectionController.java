package io.github.gabrielbbaldez.springtaint.benchmark.loginjection;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Log injection (CWE-117): a username concatenated into a log message lets an
 * attacker inject newlines and forge log entries — e.g. a fake "successful login
 * for root" — corrupting audit trails that compliance regimes (PCI-DSS, SOX) rely
 * on. Low severity, but a real integrity problem in regulated environments.
 *
 * <p>EXPECTED: log-injection (CWE-117). The single-argument {@code info} overload
 * carries the already-concatenated message.
 */
@RestController
public class LogInjectionController {

    private static final Logger log = LoggerFactory.getLogger(LogInjectionController.class);

    @GetMapping("/login-log")
    public String login(@RequestParam String username) {           // taint-source: @RequestParam username
        log.info("Login attempt for: " + username);                // taint-sink: Logger.info(String) -> EXPECTED log-injection
        return "ok";
    }
}
