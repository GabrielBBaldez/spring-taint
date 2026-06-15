package io.github.gabrielbbaldez.springtaint.config;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TaintConfigLoaderTest {

    @Test
    void loadsAllSections() throws Exception {
        try (InputStream in = getClass().getResourceAsStream("/sample-taint.yml")) {
            assertNotNull(in, "test resource /sample-taint.yml is missing");
            TaintConfig cfg = TaintConfigLoader.load(in);

            assertEquals(2, cfg.springSources().size());
            assertEquals(1, cfg.sources().size());
            assertEquals(2, cfg.sinks().size());
            assertEquals(1, cfg.sanitizers().size());

            assertEquals("sql-injection", cfg.sinks().get(0).vuln());
            assertEquals("result", cfg.sources().get(0).index());
            assertEquals("org.springframework.web.bind.annotation.RequestParam",
                    cfg.springSources().get(0).annotation());
        }
    }

    @Test
    void emptyDocumentYieldsEmptyLists() throws Exception {
        InputStream in = new ByteArrayInputStream("{}".getBytes(StandardCharsets.UTF_8));
        TaintConfig cfg = TaintConfigLoader.load(in);

        assertTrue(cfg.springSources().isEmpty());
        assertTrue(cfg.sources().isEmpty());
        assertTrue(cfg.sinks().isEmpty());
        assertTrue(cfg.sanitizers().isEmpty());
    }
}
