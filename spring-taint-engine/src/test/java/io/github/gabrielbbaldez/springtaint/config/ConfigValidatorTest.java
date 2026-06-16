package io.github.gabrielbbaldez.springtaint.config;

import io.github.gabrielbbaldez.springtaint.config.ConfigValidator.Report;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConfigValidatorTest {

    @Test
    void resolvesJdkSignaturesAndReportsBogusOnes() {
        TaintConfig config = new TaintConfig(
                List.of(), List.of(),
                List.of(
                        new SinkSpec("x", "<java.lang.String: boolean isEmpty()>", "0"),
                        new SinkSpec("x", "<com.nope.NoSuchClass: void run(java.lang.String)>", "0"),
                        new SinkSpec("x", "<java.lang.String: void noSuchMethod(int)>", "0")),
                List.of(), List.of());

        Report report = new ConfigValidator().validate(config, List.of());

        assertEquals(3, report.total());
        assertEquals(1, report.resolved());          // only String.isEmpty() resolves
        assertEquals(2, report.issues().size());
        assertFalse(report.ok());
        assertTrue(report.issues().stream().anyMatch(i -> i.signature().contains("NoSuchClass")));
        assertTrue(report.issues().stream().anyMatch(i -> i.signature().contains("noSuchMethod")));
    }
}
