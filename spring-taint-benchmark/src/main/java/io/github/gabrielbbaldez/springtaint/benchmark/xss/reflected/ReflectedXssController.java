package io.github.gabrielbbaldez.springtaint.benchmark.xss.reflected;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

/**
 * Reflected XSS: an untrusted request parameter is written into the HTTP
 * response without HTML escaping.
 *
 * <p>EXPECTED: xss (CWE-79).
 */
@RestController
public class ReflectedXssController {

    @GetMapping("/greet")
    public void greet(@RequestParam String name, HttpServletResponse response) throws IOException { // taint-source: @RequestParam name
        response.getWriter().write("<h1>Hello " + name + "</h1>"); // taint-sink: PrintWriter.write -> EXPECTED xss
    }
}
