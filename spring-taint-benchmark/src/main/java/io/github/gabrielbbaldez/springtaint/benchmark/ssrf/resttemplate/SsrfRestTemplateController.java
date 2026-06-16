package io.github.gabrielbbaldez.springtaint.benchmark.ssrf.resttemplate;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

/**
 * SSRF: a user-controlled URL is fetched server-side. An attacker can reach
 * internal services (e.g. {@code http://169.254.169.254/...}).
 *
 * <p>EXPECTED: ssrf (CWE-918).
 */
@RestController
public class SsrfRestTemplateController {

    private final RestTemplate restTemplate;

    public SsrfRestTemplateController(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    @GetMapping("/fetch")
    public String fetch(@RequestParam String url) {                  // taint-source: @RequestParam url
        return restTemplate.getForObject(url, String.class);        // taint-sink: RestTemplate.getForObject -> EXPECTED ssrf
    }
}
