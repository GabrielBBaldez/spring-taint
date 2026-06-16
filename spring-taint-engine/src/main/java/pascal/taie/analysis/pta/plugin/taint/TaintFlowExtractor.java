package pascal.taie.analysis.pta.plugin.taint;

import pascal.taie.analysis.graph.callgraph.CallGraph;
import pascal.taie.analysis.pta.PointerAnalysisResult;
import pascal.taie.ir.IR;
import pascal.taie.ir.stmt.Invoke;
import pascal.taie.ir.stmt.Stmt;
import pascal.taie.language.classes.JClass;
import pascal.taie.language.classes.JMethod;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Bridges Tai-e's package-private {@link SourcePoint} and {@link SinkPoint} to a
 * public DTO, and reconstructs the call path from source to sink.
 *
 * <p>{@code SourcePoint} and {@code SinkPoint} are package-private in Tai-e, so
 * code outside this package cannot read them. This class lives in the package
 * (on the classpath, split packages are legal) to extract source/sink locations
 * and to walk the call graph between them.
 */
public final class TaintFlowExtractor {

    /** One method on the source -> sink call path. */
    public record Hop(String className, String methodName, int line) {
    }

    /** A taint flow flattened to plain, public data the reporter can use. */
    public record ExtractedFlow(
            String sourceClass,
            String sourceMethod,
            int sourceLine,
            String sinkClass,
            int sinkLine,
            String sinkMethodClass,
            String sinkMethodName,
            String sinkMethodSignature,
            List<Hop> trace) {
    }

    /** Safety bound on call-graph traversal when reconstructing a trace. */
    private static final int MAX_BFS_METHODS = 20_000;

    /**
     * Package prefixes whose classes are framework/JDK/library internals, not the
     * analyzed application. A sink reached <em>inside</em> one of these is a
     * re-report of the same flow deep in a dependency (e.g. JdbcTemplate logging
     * the SQL it received, or the SLF4J/commons-logging facade delegating a log
     * call), so it is dropped — the application's own sink is reported instead.
     */
    private static final List<String> FRAMEWORK_PREFIXES = List.of(
            "java.", "javax.", "jakarta.", "jdk.", "sun.", "com.sun.",
            "org.springframework.", "kotlin.",
            // logging stack: app code never has its sink inside the logging facade
            "org.slf4j.", "org.apache.", "ch.qos.", "io.micrometer.",
            // common runtime libraries that may re-host a sink internally
            "reactor.", "io.netty.", "com.fasterxml.", "com.zaxxer.");

    /**
     * The outer class's simple name, used to build a {@code .java} file name. Inner and
     * anonymous classes ({@code Foo$1}, {@code Foo$Bar}) live in {@code Foo.java}, so the
     * {@code $...} suffix is stripped — otherwise source lookups (suppression, near-miss,
     * autofix) would miss findings inside nested classes.
     */
    private static String outerSimpleName(JClass clazz) {
        String simple = clazz.getSimpleName();
        int dollar = simple.indexOf('$');
        return dollar >= 0 ? simple.substring(0, dollar) : simple;
    }

    private static boolean isFrameworkClass(String fqn) {
        for (String prefix : FRAMEWORK_PREFIXES) {
            if (fqn.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    private TaintFlowExtractor() {
    }

    /**
     * @param result the pointer analysis result (holds the taint flows under
     *               {@code TaintAnalysis.class.getName()} and the call graph),
     *               or {@code null}.
     */
    @SuppressWarnings("unchecked")
    public static List<ExtractedFlow> extract(PointerAnalysisResult result) {
        List<ExtractedFlow> out = new ArrayList<>();
        if (result == null) {
            return out;
        }
        Object stored = result.getResult(TaintAnalysis.class.getName());
        if (!(stored instanceof Set<?> set)) {
            return out;
        }
        CallGraph<Invoke, JMethod> callGraph = result.getCallGraph();
        for (TaintFlow flow : (Set<TaintFlow>) set) {
            SourcePoint sourcePoint = flow.sourcePoint();
            SinkPoint sinkPoint = flow.sinkPoint();
            JMethod sourceMethod = sourcePoint.getContainer();
            Invoke sinkCall = sinkPoint.sinkCall();
            JMethod sinkContainer = sinkCall.getContainer();
            // Report the sink call the developer wrote, not the same flow re-reported
            // deep inside a framework (e.g. JdbcTemplate calling java.sql.Statement.
            // executeQuery), which would be a duplicate. The application's own code is
            // never in these framework packages.
            if (isFrameworkClass(sinkContainer.getDeclaringClass().getName())) {
                continue;
            }
            JMethod sinkMethod = sinkPoint.sink().method();

            List<Hop> trace = new ArrayList<>();
            for (JMethod method : findCallPath(callGraph, sourceMethod, sinkContainer)) {
                trace.add(new Hop(outerSimpleName(method.getDeclaringClass()),
                        method.getName(), firstLine(method)));
            }

            out.add(new ExtractedFlow(
                    outerSimpleName(sourceMethod.getDeclaringClass()),
                    sourceMethod.getName(),
                    firstLine(sourceMethod),
                    outerSimpleName(sinkContainer.getDeclaringClass()),
                    sinkCall.getLineNumber(),
                    sinkMethod.getDeclaringClass().getName(),
                    sinkMethod.getName(),
                    sinkMethod.getSignature(),
                    trace));
        }
        return out;
    }

    /**
     * Shortest call path (as methods) from {@code from} to {@code to}, inclusive.
     * Returns {@code [from]} if they are the same method, or {@code [from, to]}
     * if no path is found within the traversal bound.
     */
    private static List<JMethod> findCallPath(CallGraph<Invoke, JMethod> cg, JMethod from, JMethod to) {
        if (from.equals(to)) {
            return List.of(from);
        }
        Map<JMethod, JMethod> parent = new HashMap<>();
        Deque<JMethod> queue = new ArrayDeque<>();
        queue.add(from);
        parent.put(from, null);
        int visited = 0;
        while (!queue.isEmpty() && visited++ < MAX_BFS_METHODS) {
            JMethod current = queue.poll();
            for (JMethod callee : cg.getCalleesOfM(current)) {
                if (!parent.containsKey(callee)) {
                    parent.put(callee, current);
                    if (callee.equals(to)) {
                        return reconstructPath(parent, to);
                    }
                    queue.add(callee);
                }
            }
        }
        return List.of(from, to);
    }

    private static List<JMethod> reconstructPath(Map<JMethod, JMethod> parent, JMethod to) {
        LinkedList<JMethod> path = new LinkedList<>();
        for (JMethod method = to; method != null; method = parent.get(method)) {
            path.addFirst(method);
        }
        return path;
    }

    /** First positive source line of a method, or 0 if unavailable. */
    private static int firstLine(JMethod method) {
        try {
            IR ir = method.getIR();
            for (Stmt stmt : ir) {
                if (stmt.getLineNumber() > 0) {
                    return stmt.getLineNumber();
                }
            }
        } catch (RuntimeException ignored) {
            // IR may be unavailable for some methods; fall through.
        }
        return 0;
    }
}
