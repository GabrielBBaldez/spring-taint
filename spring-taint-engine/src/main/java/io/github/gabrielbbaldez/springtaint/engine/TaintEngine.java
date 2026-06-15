package io.github.gabrielbbaldez.springtaint.engine;

import io.github.gabrielbbaldez.springtaint.report.Finding;

import java.util.List;

/**
 * A taint-analysis backend. Implementations take an {@link AnalysisRequest} and
 * return the taint vulnerabilities found.
 */
public interface TaintEngine {

    List<Finding> analyze(AnalysisRequest request);
}
