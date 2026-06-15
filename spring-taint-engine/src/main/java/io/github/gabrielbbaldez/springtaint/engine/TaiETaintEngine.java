package io.github.gabrielbbaldez.springtaint.engine;

import io.github.gabrielbbaldez.springtaint.config.TaintConfig;
import io.github.gabrielbbaldez.springtaint.report.Finding;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * {@link TaintEngine} backed by <a href="https://github.com/pascal-lab/Tai-e">Tai-e</a>.
 *
 * <p><strong>Status: skeleton.</strong> This class assembles the Tai-e
 * invocation (call-graph + context-sensitive pointer analysis + IFDS taint
 * propagation driven by our Spring config) but the end-to-end wiring — invoking
 * Tai-e and mapping its taint flows back to {@link Finding} — is not implemented
 * yet. It currently returns an empty result and logs what it would run.
 *
 * <p>Detection correctness is tracked against {@code spring-taint-benchmark}.
 */
public final class TaiETaintEngine implements TaintEngine {

    private static final Logger log = LoggerFactory.getLogger(TaiETaintEngine.class);

    /** Tai-e CLI entry point; referenced so the dependency is exercised at build and run time. */
    private static final String TAIE_MAIN = pascal.taie.Main.class.getName();

    @Override
    public List<Finding> analyze(AnalysisRequest request) {
        String[] taieArgs = buildTaiEArguments(request);

        log.info("Tai-e entry point: {}", TAIE_MAIN);
        log.warn("Tai-e IFDS integration is not wired yet (skeleton build). "
                + "Would invoke Tai-e with: {}", String.join(" ", taieArgs));

        // TODO(engine): pascal.taie.Main.main(taieArgs); then read Tai-e's taint
        // flows and translate each into a Finding (source/flow/sink + severity).
        return new ArrayList<>();
    }

    /**
     * Builds the Tai-e argument vector: analyse the target with pointer analysis
     * and the taint plugin, configured by our generated taint config.
     */
    String[] buildTaiEArguments(AnalysisRequest request) {
        TaintConfig config = request.config();
        log.debug("Config: {} spring-sources, {} sources, {} sinks, {} sanitizers",
                config.springSources().size(), config.sources().size(),
                config.sinks().size(), config.sanitizers().size());

        // Real Tai-e option shape: pointer analysis (pta) with the taint plugin
        // enabled via a generated taint-config file. The generated file fuses our
        // library sinks/sanitizers with param-sources synthesised from the Spring
        // annotation layer; producing it is part of the engine work still to come.
        return new String[] {
                "-cp", request.target().toString(),
                "-a", "pta=cs:2-obj;taint-config:<generated>.yml"
        };
    }
}
