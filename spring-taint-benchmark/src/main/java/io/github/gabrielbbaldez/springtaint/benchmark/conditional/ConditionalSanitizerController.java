package io.github.gabrielbbaldez.springtaint.benchmark.conditional;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

import java.io.IOException;

/**
 * Conditional sanitizer: the value is escaped only on the {@code trusted=false}
 * branch, so it is still vulnerable when {@code trusted=true}. The analyzer must
 * report the unsanitized path.
 *
 * <p>EXPECTED: xss (CWE-79) — a tainted path reaches the sink.
 */
@RestController
public class ConditionalSanitizerController {

    @GetMapping("/cond")
    public void process(@RequestParam String input,
                        @RequestParam(defaultValue = "false") boolean trusted,
                        HttpServletResponse response) throws IOException { // taint-source: @RequestParam input
        String out = trusted ? input : HtmlUtils.htmlEscape(input);        // sanitized only when !trusted
        response.getWriter().write("<p>" + out + "</p>");                  // taint-sink: PrintWriter.write -> EXPECTED xss
    }
}
