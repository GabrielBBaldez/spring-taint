package io.github.gabrielbbaldez.springtaint.benchmark.cmdi.direct;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

/**
 * Command injection: an untrusted host value is concatenated into a shell
 * command. A payload such as {@code 8.8.8.8; rm -rf /} runs arbitrary commands.
 *
 * <p>EXPECTED: command-injection (CWE-78).
 */
@RestController
public class CommandInjectionController {

    @GetMapping("/ping")
    public void ping(@RequestParam String host) throws IOException {     // taint-source: @RequestParam host
        @SuppressWarnings("deprecation")
        Process process = Runtime.getRuntime().exec("ping -c 1 " + host); // taint-sink: Runtime.exec(String) -> EXPECTED command-injection
        process.destroy();
    }
}
