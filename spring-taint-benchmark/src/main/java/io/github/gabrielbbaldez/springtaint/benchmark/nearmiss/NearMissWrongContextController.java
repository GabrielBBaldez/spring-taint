package io.github.gabrielbbaldez.springtaint.benchmark.nearmiss;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

import java.io.IOException;

/**
 * Near-miss (right sanitizer, wrong context): {@code htmlEscape} protects against
 * XSS, not open redirect. The escaped URL still redirects wherever the attacker
 * wants. The right sanitizer applied in the wrong context gives false confidence.
 *
 * <p>EXPECTED: open-redirect (CWE-601), flagged as a near-miss sanitizer. The
 * sanitizer clears the taint for the analyzer, so this is a false negative until
 * sanitizer context is modelled.
 */
@RestController
public class NearMissWrongContextController {

    @GetMapping("/nm/redirect")
    public void go(@RequestParam String url, HttpServletResponse response) throws IOException { // taint-source: @RequestParam url
        String safe = HtmlUtils.htmlEscape(url);                        // near-miss: wrong context for a redirect
        response.sendRedirect(safe);                                    // taint-sink -> EXPECTED open-redirect
    }
}
