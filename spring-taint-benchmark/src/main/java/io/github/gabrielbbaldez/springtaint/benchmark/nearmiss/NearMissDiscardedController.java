package io.github.gabrielbbaldez.springtaint.benchmark.nearmiss;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

import java.io.IOException;

/**
 * Near-miss (sanitizer result discarded): {@code htmlEscape} returns a new value
 * rather than mutating its argument, but the developer ignores the return value and
 * then writes the original, unescaped input. A common and devastating mistake.
 *
 * <p>EXPECTED: xss (CWE-79), flagged as a near-miss sanitizer.
 */
@RestController
public class NearMissDiscardedController {

    @GetMapping("/nm/discarded")
    public void render(@RequestParam String input, HttpServletResponse response) throws IOException { // taint-source: @RequestParam input
        HtmlUtils.htmlEscape(input);                                    // near-miss: return value discarded
        response.getWriter().write("<div>" + input + "</div>");        // uses the original -> EXPECTED xss
    }
}
