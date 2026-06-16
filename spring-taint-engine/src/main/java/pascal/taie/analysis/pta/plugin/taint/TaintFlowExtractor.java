package pascal.taie.analysis.pta.plugin.taint;

import pascal.taie.ir.IR;
import pascal.taie.ir.stmt.Invoke;
import pascal.taie.ir.stmt.Stmt;
import pascal.taie.language.classes.JMethod;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Bridges Tai-e's package-private {@link SourcePoint} and {@link SinkPoint} to a
 * public DTO.
 *
 * <p>{@code SourcePoint} and {@code SinkPoint} are package-private in Tai-e, so
 * code outside {@code pascal.taie.analysis.pta.plugin.taint} cannot read them.
 * This class lives in that package (on the classpath, split packages are legal)
 * purely to extract the source/sink locations from each {@link TaintFlow}.
 */
public final class TaintFlowExtractor {

    /** A taint flow flattened to plain, public data the reporter can use. */
    public record ExtractedFlow(
            String sourceClass,
            String sourceMethod,
            int sourceLine,
            String sinkClass,
            int sinkLine,
            String sinkMethodClass,
            String sinkMethodName,
            String sinkMethodSignature) {
    }

    private TaintFlowExtractor() {
    }

    /**
     * @param taintFlowSet the value stored by Tai-e under
     *                     {@code TaintAnalysis.class.getName()} (a {@code Set<TaintFlow>}),
     *                     or {@code null}.
     */
    @SuppressWarnings("unchecked")
    public static List<ExtractedFlow> extract(Object taintFlowSet) {
        List<ExtractedFlow> result = new ArrayList<>();
        if (!(taintFlowSet instanceof Set<?> set)) {
            return result;
        }
        for (TaintFlow flow : (Set<TaintFlow>) set) {
            SourcePoint sourcePoint = flow.sourcePoint();
            SinkPoint sinkPoint = flow.sinkPoint();
            JMethod sourceMethod = sourcePoint.getContainer();
            Invoke sinkCall = sinkPoint.sinkCall();
            JMethod sinkContainer = sinkCall.getContainer();
            JMethod sinkMethod = sinkPoint.sink().method();
            result.add(new ExtractedFlow(
                    sourceMethod.getDeclaringClass().getSimpleName(),
                    sourceMethod.getName(),
                    firstLine(sourceMethod),
                    sinkContainer.getDeclaringClass().getSimpleName(),
                    sinkCall.getLineNumber(),
                    sinkMethod.getDeclaringClass().getName(),
                    sinkMethod.getName(),
                    sinkMethod.getSignature()));
        }
        return result;
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
