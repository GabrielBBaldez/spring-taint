package io.github.gabrielbbaldez.springtaint.benchmark.xss.safe;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

import java.io.IOException;

/**
 * SAFE counterpart of the reflected XSS case. The value is HTML-escaped with
 * {@link HtmlUtils#htmlEscape(String)} before being written to the response.
 *
 * <p>EXPECTED: safe — this flow must NOT be flagged (measures precision).
 */
@RestController
public class SafeXssController {

    @GetMapping("/greet-safe")
    public void greet(@RequestParam String name, HttpServletResponse response) throws IOException { // taint-source: @RequestParam name
        String safe = HtmlUtils.htmlEscape(name);                  // sanitizer
        response.getWriter().write("<h1>Hello " + safe + "</h1>"); // sanitized before sink -> EXPECTED safe
    }
}
