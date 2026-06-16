package io.github.gabrielbbaldez.springtaint.autofix;

import io.github.gabrielbbaldez.springtaint.report.Finding;
import io.github.gabrielbbaldez.springtaint.report.FlowStep;
import io.github.gabrielbbaldez.springtaint.report.Severity;
import io.github.gabrielbbaldez.springtaint.testutil.Fixtures;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AutofixGeneratorTest {

    private static Finding sqlFinding(String file, int sinkLine) {
        return new Finding("sql-injection", Severity.CRITICAL, "msg", null, file, sinkLine,
                List.of(new FlowStep(file, sinkLine - 1, "source"), new FlowStep(file, sinkLine, "sink")));
    }

    @Test
    void parameterizesInlineConcatAndStripsQuotes(@TempDir Path dir) throws Exception {
        Fixtures.write(dir, "p/Foo.java", """
                package p;
                class Foo {
                    org.springframework.jdbc.core.JdbcTemplate jdbc;
                    int run(String name) {
                        return jdbc.update("SELECT * FROM u WHERE n = '" + name + "'");
                    }
                }
                """);
        List<Patch> patches = new AutofixGenerator().generate(List.of(sqlFinding("Foo.java", 5)), dir);

        assertEquals(1, patches.size());
        assertTrue(patches.get(0).newSource().contains("\"SELECT * FROM u WHERE n = ?\""),
                "quotes around the bound value should be dropped");
        assertTrue(patches.get(0).newSource().contains("update(\"SELECT * FROM u WHERE n = ?\", name)"));
        assertTrue(patches.get(0).highConfidence());
    }

    @Test
    void scopesVariableLookupToTheSinkMethod(@TempDir Path dir) throws Exception {
        // Two methods declare `q`; the fix must use run()'s `q` (built from `id`), not safe()'s.
        Fixtures.write(dir, "p/Foo.java", """
                package p;
                class Foo {
                    org.springframework.jdbc.core.JdbcTemplate jdbc;
                    void safe() {
                        String q = "SELECT 1 FROM dual WHERE x = " + Constants.SAFE;
                    }
                    int run(String id) {
                        String q = "DELETE FROM users WHERE id = " + id;
                        return jdbc.update(q);
                    }
                }
                """);
        List<Patch> patches = new AutofixGenerator().generate(List.of(sqlFinding("Foo.java", 9)), dir);

        assertEquals(1, patches.size());
        String fixed = patches.get(0).newSource();
        assertTrue(fixed.contains("\"DELETE FROM users WHERE id = ?\""), "should parameterize run()'s query");
        assertFalse(fixed.contains("WHERE x = ?"), "must not touch the unrelated safe() query");
    }

    @Test
    void skipsAmbiguousFileNamesToAvoidRewritingTheWrongFile(@TempDir Path dir) throws Exception {
        Fixtures.write(dir, "p/Foo.java", """
                package p;
                class Foo { org.springframework.jdbc.core.JdbcTemplate jdbc;
                    int run(String id) { return jdbc.update("DELETE FROM t WHERE id = " + id); } }
                """);
        Fixtures.write(dir, "q/Foo.java", """
                package q;
                class Foo { void unrelated() {} }
                """);
        List<Patch> patches = new AutofixGenerator().generate(List.of(sqlFinding("Foo.java", 3)), dir);

        assertTrue(patches.isEmpty(), "a duplicated simple name must not be auto-fixed");
    }
}
