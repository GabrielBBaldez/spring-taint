package io.github.gabrielbbaldez.springtaint.benchmark.misconfig;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * A session cookie set without the HttpOnly and Secure flags: it is readable from
 * JavaScript (so an XSS can steal it) and may be sent over plain HTTP.
 *
 * <p>EXPECTED: insecure-config (setHttpOnly(false), setSecure(false)).
 */
@RestController
public class InsecureCookieController {

    @GetMapping("/set-cookie")
    public void setCookie(HttpServletResponse response) {
        Cookie cookie = new Cookie("session", "token-value");
        cookie.setHttpOnly(false);              // misconfig: readable from JavaScript
        cookie.setSecure(false);                // misconfig: sent over plain HTTP
        response.addCookie(cookie);
    }
}
