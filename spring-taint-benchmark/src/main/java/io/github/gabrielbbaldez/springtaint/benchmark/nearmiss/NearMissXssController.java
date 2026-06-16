package io.github.gabrielbbaldez.springtaint.benchmark.nearmiss;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

/**
 * Near-miss (blacklist instead of whitelist): the developer removes the literal
 * {@code <script>} tag and believes it is safe, but blacklists are trivially
 * bypassed ({@code <scr<script>ipt>} collapses to {@code <script>}, plus
 * {@code <SCRIPT>}, {@code <img onerror=>}, …). The correct fix is contextual
 * escaping.
 *
 * <p>EXPECTED: xss (CWE-79), flagged as a near-miss sanitizer.
 */
@RestController
public class NearMissXssController {

    @GetMapping("/nm/xss")
    public void render(@RequestParam String input, HttpServletResponse response) throws IOException { // taint-source: @RequestParam input
        String safe = input.replace("<script>", "");                    // near-miss: blacklist is bypassable
        response.getWriter().write("<div>" + safe + "</div>");          // taint-sink -> EXPECTED xss
    }
}
