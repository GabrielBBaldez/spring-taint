package io.github.gabrielbbaldez.demo.web;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

/** Command injection — one vulnerable endpoint, one with no user input in the command. */
@RestController
public class OpsController {

    /** VULNERABLE: a user-controlled host is concatenated into a shell command. */
    @GetMapping("/ping")
    public String ping(@RequestParam String host) throws IOException {
        Process process = Runtime.getRuntime().exec("ping -c 1 " + host);     // EXPECTED: command-injection
        return "pid=" + process.pid();
    }

    /** SAFE: a fixed command with no request data — must NOT be flagged. */
    @GetMapping("/uptime")
    public String uptime() throws IOException {
        Process process = Runtime.getRuntime().exec("uptime");                // safe: no tainted input
        return "pid=" + process.pid();
    }
}
