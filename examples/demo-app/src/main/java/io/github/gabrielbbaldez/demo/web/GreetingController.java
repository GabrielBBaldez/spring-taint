package io.github.gabrielbbaldez.demo.web;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

import java.io.IOException;

/** Reflected XSS — one vulnerable endpoint, one correctly-escaped one. */
@RestController
public class GreetingController {

    /** VULNERABLE: the raw request parameter is written into the HTML response. */
    @GetMapping("/greet")
    public void greet(@RequestParam String name, HttpServletResponse response) throws IOException {
        response.getWriter().write("<h1>Hello, " + name + "!</h1>");          // EXPECTED: xss
    }

    /** SAFE: the value is HTML-escaped first — must NOT be flagged. */
    @GetMapping("/greet-safe")
    public void greetSafe(@RequestParam String name, HttpServletResponse response) throws IOException {
        response.getWriter().write("<h1>Hello, " + HtmlUtils.htmlEscape(name) + "!</h1>");  // safe
    }
}
