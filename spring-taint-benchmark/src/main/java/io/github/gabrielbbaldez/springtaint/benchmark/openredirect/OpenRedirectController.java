package io.github.gabrielbbaldez.springtaint.benchmark.openredirect;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

/**
 * Open redirect: a user-controlled URL is used as the redirect target, enabling
 * phishing redirects to attacker-controlled sites.
 *
 * <p>EXPECTED: open-redirect (CWE-601). The sink is called directly on the
 * {@code HttpServletResponse} parameter (an interface), which is a known hard
 * case for the current entry-point modelling.
 */
@RestController
public class OpenRedirectController {

    @GetMapping("/go")
    public void go(@RequestParam String url, HttpServletResponse response) throws IOException { // taint-source: @RequestParam url
        response.sendRedirect(url);                                                             // taint-sink: HttpServletResponse.sendRedirect -> EXPECTED open-redirect
    }
}
