package io.github.gabrielbbaldez.springtaint.benchmark.templateinjection;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.thymeleaf.ITemplateEngine;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

/**
 * Server-Side Template Injection (SSTI): a user-controlled template name/body is
 * processed by Thymeleaf. A payload using the expression syntax
 * ({@code __${T(java.lang.Runtime).getRuntime().exec(...)}__::.x}) runs code on
 * the server — a real class of Spring Boot CVE.
 *
 * <p>EXPECTED: template-injection (CWE-1336). The engine is typed as the
 * {@code ITemplateEngine} interface so the sink matches the call site.
 */
@RestController
public class ThymeleafSstiController {

    private final ITemplateEngine templateEngine = new TemplateEngine();

    @GetMapping("/render")
    public String render(@RequestParam String page) {              // taint-source: @RequestParam page
        return templateEngine.process(page, new Context());        // taint-sink: ITemplateEngine.process -> EXPECTED template-injection
    }
}
