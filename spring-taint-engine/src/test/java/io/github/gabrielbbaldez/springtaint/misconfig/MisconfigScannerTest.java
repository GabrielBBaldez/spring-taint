package io.github.gabrielbbaldez.springtaint.misconfig;

import io.github.gabrielbbaldez.springtaint.report.Finding;
import io.github.gabrielbbaldez.springtaint.testutil.Fixtures;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

class MisconfigScannerTest {

    private static final String LOGGED = "Sensitive data passed to a logger";

    @Test
    void flagsSensitiveValueWrittenToLog(@TempDir Path dir) throws Exception {
        Path classes = Fixtures.compile(dir, "p.Leak", """
                package p;
                import org.slf4j.Logger;
                import org.slf4j.LoggerFactory;
                class Account { String getPassword() { return ""; } }
                class Leak {
                    static final Logger log = LoggerFactory.getLogger(Leak.class);
                    void doIt(Account a) { log.info("pw " + a.getPassword()); }
                }
                """);
        List<Finding> out = new MisconfigScanner().scan(classes);
        assertTrue(out.stream().anyMatch(f -> f.message().contains(LOGGED)), () -> out.toString());
    }

    @Test
    void doesNotFlagSensitiveGetterUsedOutsideLogging(@TempDir Path dir) throws Exception {
        // Regression: a sensitive getter used for a non-logging purpose must not taint a
        // later, unrelated log call.
        Path classes = Fixtures.compile(dir, "p.Safe", """
                package p;
                import org.slf4j.Logger;
                import org.slf4j.LoggerFactory;
                class Acct { String getPassword() { return ""; } String getName() { return ""; } }
                class Safe {
                    static final Logger log = LoggerFactory.getLogger(Safe.class);
                    boolean check(String a, String b) { return a.equals(b); }
                    void doIt(Acct a) {
                        boolean ok = check("x", a.getPassword());
                        log.info("hello " + a.getName());
                    }
                }
                """);
        List<Finding> out = new MisconfigScanner().scan(classes);
        assertTrue(out.stream().noneMatch(f -> f.message().contains(LOGGED)), () -> out.toString());
    }
}
