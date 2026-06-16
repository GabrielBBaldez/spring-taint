package io.github.gabrielbbaldez.springtaint.benchmark.spel;

import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * SpEL injection: a user-controlled expression is parsed and evaluated, allowing
 * arbitrary code execution (e.g. {@code T(java.lang.Runtime).getRuntime().exec(...)}).
 *
 * <p>EXPECTED: spel-injection (CWE-917).
 */
@RestController
public class SpelInjectionController {

    private final SpelExpressionParser parser = new SpelExpressionParser();

    @GetMapping("/eval")
    public Object eval(@RequestParam String expression) {       // taint-source: @RequestParam expression
        return parser.parseExpression(expression).getValue();  // taint-sink: ExpressionParser.parseExpression -> EXPECTED spel-injection
    }
}
