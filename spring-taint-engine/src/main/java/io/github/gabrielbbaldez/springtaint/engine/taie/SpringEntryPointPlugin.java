package io.github.gabrielbbaldez.springtaint.engine.taie;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pascal.taie.analysis.pta.core.solver.DeclaredParamProvider;
import pascal.taie.analysis.pta.core.solver.EntryPoint;
import pascal.taie.analysis.pta.core.solver.Solver;
import pascal.taie.analysis.pta.plugin.Plugin;
import pascal.taie.language.classes.JClass;
import pascal.taie.language.classes.JMethod;

/**
 * Tai-e plugin that makes Spring entry points reachable.
 *
 * <p>Spring web/messaging handlers have no explicit caller — the framework
 * invokes them by reflection — so they are not in the call graph by default,
 * and the taint analysis would never see them. This plugin mirrors Tai-e's own
 * {@code EntryPointHandler}: for every method carrying a Spring source
 * annotation it registers an entry point with a {@link DeclaredParamProvider},
 * which also mocks the handler's fields (e.g. the injected service/repository)
 * a few levels deep so the interprocedural flow can be followed.
 *
 * <p>Registered via the pta option {@code plugins:[...]}.
 */
public final class SpringEntryPointPlugin implements Plugin {

    private static final Logger log = LoggerFactory.getLogger(SpringEntryPointPlugin.class);

    /**
     * Depth of mocked field/parameter objects. The chain
     * controller -> service -> repository -> JdbcTemplate needs depth 3, so 4
     * leaves a small margin for one extra injected layer.
     */
    private static final int PARAM_OBJECT_DEPTH = 4;

    private Solver solver;

    @Override
    public void setSolver(Solver solver) {
        this.solver = solver;
    }

    @Override
    public void onStart() {
        int count = 0;
        for (JClass clazz : solver.getHierarchy().applicationClasses().toList()) {
            for (JMethod method : clazz.getDeclaredMethods()) {
                if (SpringSources.isEntry(method)) {
                    solver.addEntryPoint(new EntryPoint(method,
                            new DeclaredParamProvider(method, solver.getHeapModel(), PARAM_OBJECT_DEPTH)));
                    count++;
                    log.debug("Spring entry point: {}", method.getSignature());
                }
            }
        }
        log.info("Spring layer: registered {} entry point(s)", count);
    }
}
