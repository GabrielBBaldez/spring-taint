package io.github.gabrielbbaldez.springtaint.engine;

import io.github.gabrielbbaldez.springtaint.config.TaintConfig;

import java.nio.file.Path;
import java.util.List;

/**
 * Everything the engine needs for one analysis run.
 *
 * @param target           compiled project to analyse (a directory of {@code .class} files or a JAR)
 * @param libraryClasspath dependencies needed to resolve the target (e.g. Spring jars),
 *                         path-separator-joined, or {@code null}
 * @param config           the loaded taint configuration
 * @param severities       severities to report, or empty to report all
 * @param verbose          whether to produce the full flow trace
 */
public record AnalysisRequest(
        Path target,
        String libraryClasspath,
        TaintConfig config,
        List<String> severities,
        boolean verbose) {

    public AnalysisRequest {
        severities = (severities == null) ? List.of() : List.copyOf(severities);
    }
}
