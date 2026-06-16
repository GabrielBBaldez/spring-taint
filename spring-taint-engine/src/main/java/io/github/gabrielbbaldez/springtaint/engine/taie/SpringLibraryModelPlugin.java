package io.github.gabrielbbaldez.springtaint.engine.taie;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pascal.taie.analysis.pta.core.cs.element.CSMethod;
import pascal.taie.analysis.pta.core.heap.Descriptor;
import pascal.taie.analysis.pta.core.heap.Obj;
import pascal.taie.analysis.pta.core.solver.Solver;
import pascal.taie.analysis.pta.plugin.Plugin;
import pascal.taie.ir.exp.InvokeDynamic;
import pascal.taie.ir.exp.Var;
import pascal.taie.ir.proginfo.MethodRef;
import pascal.taie.ir.stmt.Invoke;
import pascal.taie.ir.stmt.Stmt;
import pascal.taie.language.classes.JMethod;
import pascal.taie.language.type.ClassType;
import pascal.taie.language.type.Type;

import java.util.Set;

/**
 * Models a few library "factory" methods so their return value gets a tracked
 * object under {@code only-app} mode.
 *
 * <p>Without this, sinks whose receiver comes straight from a library call are
 * never resolved — the receiver has no points-to object, so no call edge to the
 * sink method is built and the taint analysis never sees it. Examples:
 * <pre>
 *   response.getWriter().write(tainted);   // XSS  — PrintWriter from getWriter()
 *   Runtime.getRuntime().exec(tainted);    // RCE  — Runtime from getRuntime()
 * </pre>
 *
 * <p>For each call to a configured factory method in application code, this
 * injects a mock object of the call's (instantiable) return type into the
 * result variable, so the following call on it resolves.
 */
public final class SpringLibraryModelPlugin implements Plugin {

    private static final Logger log = LoggerFactory.getLogger(SpringLibraryModelPlugin.class);

    private static final Descriptor LIBRARY_RETURN = () -> "SpringLibraryReturnObj";

    /** Library factory methods whose return object we model (matched by name). */
    private static final Set<String> FACTORY_METHODS = Set.of(
            "getWriter",        // ServletResponse#getWriter -> PrintWriter
            "getOutputStream",  // ServletResponse#getOutputStream -> ServletOutputStream
            "getRuntime");      // Runtime#getRuntime -> Runtime

    private Solver solver;

    @Override
    public void setSolver(Solver solver) {
        this.solver = solver;
    }

    @Override
    public void onNewCSMethod(CSMethod csMethod) {
        JMethod method = csMethod.getMethod();
        if (!method.getDeclaringClass().isApplication() || method.isAbstract()) {
            return;
        }
        for (Stmt stmt : method.getIR()) {
            if (stmt instanceof Invoke invoke) {
                modelIfFactory(csMethod, invoke);
            }
        }
    }

    private void modelIfFactory(CSMethod csMethod, Invoke invoke) {
        Var result = invoke.getResult();
        if (result == null) {
            return;
        }
        // InvokeDynamic (string concatenation, lambdas) has no method ref.
        if (invoke.getInvokeExp() instanceof InvokeDynamic) {
            return;
        }
        MethodRef ref = invoke.getMethodRef();
        if (!FACTORY_METHODS.contains(ref.getName())) {
            return;
        }
        Type returnType = ref.getReturnType();
        if (!isInstantiable(returnType)) {
            return;
        }
        Obj mock = solver.getHeapModel().getMockObj(
                LIBRARY_RETURN, "factory:" + ref, returnType, csMethod.getMethod());
        solver.addVarPointsTo(csMethod.getContext(), result,
                solver.getContextSelector().getEmptyContext(), mock);
        log.debug("Modelled library factory return: {} -> {}", ref, returnType);
    }

    private static boolean isInstantiable(Type type) {
        return type instanceof ClassType classType && !classType.getJClass().isAbstract();
    }
}
