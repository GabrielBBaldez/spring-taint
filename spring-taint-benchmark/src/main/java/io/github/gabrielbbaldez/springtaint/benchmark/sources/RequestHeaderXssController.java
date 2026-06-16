package io.github.gabrielbbaldez.springtaint.benchmark.sources;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

/**
 * Reflected XSS where the source is a {@code @RequestHeader}.
 *
 * <p>EXPECTED: xss (CWE-79).
 */
@RestController
public class RequestHeaderXssController {

    @GetMapping("/echo")
    public void echo(@RequestHeader("X-Message") String message,
                     HttpServletResponse response) throws IOException { // taint-source: @RequestHeader message
        response.getWriter().write("<p>" + message + "</p>");          // taint-sink: PrintWriter.write -> EXPECTED xss
    }
}
