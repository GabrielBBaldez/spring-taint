package io.github.gabrielbbaldez.springtaint.nearmiss;

import io.github.gabrielbbaldez.springtaint.report.Finding;
import io.github.gabrielbbaldez.springtaint.report.FlowStep;
import io.github.gabrielbbaldez.springtaint.report.Severity;
import io.github.gabrielbbaldez.springtaint.testutil.Fixtures;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NearMissAnnotatorTest {

    private static Finding finding(String rule, String file, int sinkLine) {
        return new Finding(rule, Severity.HIGH, "msg", null, file, sinkLine,
                List.of(new FlowStep(file, sinkLine - 2, "source"), new FlowStep(file, sinkLine, "sink")));
    }

    @Test
    void flagsInsufficientSqlSanitization(@TempDir Path dir) throws Exception {
        Fixtures.write(dir, "C.java", """
                package p;
                class C {
                    int run(String name, Jdbc jdbc) {
                        String safe = name.replaceAll("'", "");
                        return jdbc.update("SELECT * FROM u WHERE n = '" + safe + "'");
                    }
                }
                """);
        List<Finding> out = new NearMissAnnotator().annotate(List.of(finding("sql-injection", "C.java", 5)), dir);
        assertNotNull(out.get(0).nearMiss());
        assertTrue(out.get(0).nearMiss().contains("SQL injection"));
    }

    @Test
    void flagsDiscardedSanitizerResult(@TempDir Path dir) throws Exception {
        Fixtures.write(dir, "C.java", """
                package p;
                class C {
                    void render(String in, Resp resp) {
                        HtmlUtils.htmlEscape(in);
                        resp.getWriter().write("<div>" + in + "</div>");
                    }
                }
                """);
        List<Finding> out = new NearMissAnnotator().annotate(List.of(finding("xss", "C.java", 5)), dir);
        assertNotNull(out.get(0).nearMiss());
        assertTrue(out.get(0).nearMiss().contains("discarded"));
    }

    @Test
    void detectsWrongContextEscapeBeforeRedirectAsNewFinding(@TempDir Path dir) throws Exception {
        Fixtures.write(dir, "C.java", """
                package p;
                class C {
                    void go(String url, Resp resp) {
                        String safe = HtmlUtils.htmlEscape(url);
                        resp.sendRedirect(safe);
                    }
                }
                """);
        List<Finding> out = new NearMissAnnotator().annotate(List.of(), dir);
        assertEquals(1, out.size());
        assertEquals("open-redirect", out.get(0).ruleId());
        assertTrue(out.get(0).nearMiss().contains("open redirect"));
    }

    @Test
    void doesNotFlagWrongContextAcrossDifferentMethods(@TempDir Path dir) throws Exception {
        // `url` is escaped in display(); a same-named local in redirect() must not be flagged.
        Fixtures.write(dir, "C.java", """
                package p;
                class C {
                    void display(String in) {
                        String url = HtmlUtils.htmlEscape(in);
                        model.add(url);
                    }
                    void redirect(String dest, Resp resp) {
                        String url = dest;
                        resp.sendRedirect(url);
                    }
                }
                """);
        List<Finding> out = new NearMissAnnotator().annotate(List.of(), dir);
        assertTrue(out.isEmpty(), "escaped variable scope must not leak across methods");
    }

    @Test
    void leavesUnrelatedFindingUnannotated(@TempDir Path dir) throws Exception {
        Fixtures.write(dir, "C.java", """
                package p;
                class C {
                    int run(String id, Jdbc jdbc) {
                        return jdbc.update("DELETE FROM t WHERE id = " + id);
                    }
                }
                """);
        List<Finding> out = new NearMissAnnotator().annotate(List.of(finding("sql-injection", "C.java", 4)), dir);
        assertNull(out.get(0).nearMiss());
    }

    @Test
    void detectsWrongContextEvenWithAControlFlowBlockBetween(@TempDir Path dir) throws Exception {
        // A closing brace of an if/for/try between the escape and the redirect must NOT
        // clear the escaped-variable scope -- only a method boundary should.
        Fixtures.write(dir, "C.java", """
                package p;
                class C {
                    void go(String url, boolean cond, Resp resp) {
                        String safe = HtmlUtils.htmlEscape(url);
                        if (cond) {
                            audit(url);
                        }
                        resp.sendRedirect(safe);
                    }
                }
                """);
        List<Finding> out = new NearMissAnnotator().annotate(List.of(), dir);
        assertEquals(1, out.size(), "an if-block must not end the escaped-variable scope");
        assertEquals("open-redirect", out.get(0).ruleId());
    }
}
