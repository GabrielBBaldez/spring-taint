package io.github.gabrielbbaldez.springtaint.engine.taie;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pascal.taie.analysis.pta.plugin.taint.CallSource;
import pascal.taie.analysis.pta.plugin.taint.IndexRef;
import pascal.taie.analysis.pta.plugin.taint.ParamSource;
import pascal.taie.analysis.pta.plugin.taint.Source;
import pascal.taie.analysis.pta.plugin.taint.TaintConfigProvider;
import pascal.taie.analysis.pta.plugin.taint.TaintTransfer;
import pascal.taie.analysis.pta.plugin.util.InvokeUtils;
import pascal.taie.language.classes.ClassHierarchy;
import pascal.taie.language.classes.JClass;
import pascal.taie.language.classes.JField;
import pascal.taie.language.classes.JMethod;
import pascal.taie.language.type.Type;
import pascal.taie.language.type.TypeSystem;

import java.util.ArrayList;
import java.util.List;

/**
 * Generates Tai-e {@link ParamSource}s from Spring source annotations.
 *
 * <p>Tai-e's YAML config can only declare sources by concrete method signature.
 * Spring sources are annotation-driven, so this provider scans the application
 * classes and emits one {@code param} source per annotated parameter
 * ({@code @RequestParam}, {@code @KafkaListener} payload, …). It merges with the
 * sinks/sanitizers/transfers loaded from the YAML config.
 *
 * <p>Registered via the pta option {@code taint-config-providers:[...]}; Tai-e
 * instantiates it via the {@code (ClassHierarchy, TypeSystem)} constructor.
 */
public final class SpringTaintConfigProvider extends TaintConfigProvider {

    private static final Logger log = LoggerFactory.getLogger(SpringTaintConfigProvider.class);

    public SpringTaintConfigProvider(ClassHierarchy hierarchy, TypeSystem typeSystem) {
        super(hierarchy, typeSystem);
    }

    private static final String REPOSITORY_ANNOTATION = "org.springframework.stereotype.Repository";
    private static final String FEIGN_ANNOTATION = "org.springframework.cloud.openfeign.FeignClient";
    private static final String STRING_TYPE = "java.lang.String";

    @Override
    protected List<Source> sources() {
        List<Source> sources = new ArrayList<>();
        int paramSources = 0;
        int storeSources = 0;
        int feignSources = 0;
        for (JClass clazz : hierarchy.applicationClasses().toList()) {
            boolean isRepository = clazz.hasAnnotation(REPOSITORY_ANNOTATION);
            boolean isFeignClient = clazz.hasAnnotation(FEIGN_ANNOTATION);
            for (JMethod method : clazz.getDeclaredMethods()) {
                // Annotation-driven request inputs.
                for (int index : SpringSources.taintedParams(method)) {
                    Type type = method.getParamType(index);
                    sources.add(new ParamSource(method,
                            new IndexRef(IndexRef.Kind.VAR, index, null), type));
                    paramSources++;
                }
                // Persistence reads: data returned by a @Repository read method is
                // untrusted (it may have been stored by an earlier request) — this
                // models stored / second-order injection. Limited to String returns
                // to stay precise.
                if (isRepository && isPersistenceRead(method)) {
                    sources.add(new CallSource(method,
                            new IndexRef(IndexRef.Kind.VAR, InvokeUtils.RESULT, null),
                            method.getReturnType()));
                    storeSources++;
                }
                // Microservice calls: a value returned by a @FeignClient method comes
                // from a downstream service and is untrusted at the caller. Same
                // String-only restriction as persistence reads to stay precise.
                if (isFeignClient && returnsString(method)) {
                    sources.add(new CallSource(method,
                            new IndexRef(IndexRef.Kind.VAR, InvokeUtils.RESULT, null),
                            method.getReturnType()));
                    feignSources++;
                }
            }
        }
        log.info("Spring layer: generated {} param source(s), {} persistence-read source(s) "
                + "and {} feign-client source(s)", paramSources, storeSources, feignSources);
        return sources;
    }

    /**
     * Models value objects (DTOs, form/command beans, entities) as taint containers:
     * a tainted bean's {@code String} getter returns a tainted value, and a
     * {@code String} setter taints the bean. This catches flows where a
     * {@code @RequestBody}/built bean carries untrusted data into a sink via its
     * accessors (a common pattern that pure source/sink matching misses). Restricted
     * to {@code String} accessors of application classes to stay precise.
     */
    @Override
    protected List<TaintTransfer> transfers() {
        IndexRef base = new IndexRef(IndexRef.Kind.VAR, InvokeUtils.BASE, null);
        IndexRef result = new IndexRef(IndexRef.Kind.VAR, InvokeUtils.RESULT, null);
        IndexRef arg0 = new IndexRef(IndexRef.Kind.VAR, 0, null);
        List<TaintTransfer> transfers = new ArrayList<>();
        for (JClass clazz : hierarchy.applicationClasses().toList()) {
            for (JMethod method : clazz.getDeclaredMethods()) {
                if (method.isStatic() || method.isAbstract()) {
                    continue;
                }
                String name = method.getName();
                if (method.getParamCount() == 0 && returnsString(method)
                        && (name.startsWith("get") || name.startsWith("is") || declaresField(clazz, name))) {
                    // getter or record accessor: the bean's taint flows out to the returned
                    // String. A record's accessor is named after its component (e.g. term()),
                    // so it is matched by the field-name check, not the get*/is* prefix.
                    transfers.add(new TaintTransfer(method, base, result, method.getReturnType()));
                } else if (method.getParamCount() == 1 && name.startsWith("set")
                        && STRING_TYPE.equals(method.getParamType(0).getName())) {
                    // setter: a tainted String taints the bean
                    transfers.add(new TaintTransfer(method, arg0, base, clazz.getType()));
                }
            }
        }
        log.info("Spring layer: generated {} bean accessor transfer(s)", transfers.size());
        return transfers;
    }

    /** A non-static method returning {@code java.lang.String}. */
    private static boolean returnsString(JMethod method) {
        return !method.isStatic() && STRING_TYPE.equals(method.getReturnType().getName());
    }

    /**
     * Whether {@code clazz} declares a field named {@code name} -- true for a record's
     * accessor (named after its component) and for field-named accessors that don't use
     * the {@code get}/{@code is} convention. Keeps the bean model precise: only methods
     * backed by an actual field are treated as accessors.
     */
    private static boolean declaresField(JClass clazz, String name) {
        for (JField field : clazz.getDeclaredFields()) {
            if (field.getName().equals(name)) {
                return true;
            }
        }
        return false;
    }

    /** A @Repository read method ({@code find*}/{@code get*}/...) returning a String. */
    private static boolean isPersistenceRead(JMethod method) {
        if (!returnsString(method)) {
            return false;
        }
        String name = method.getName();
        return name.startsWith("find") || name.startsWith("get") || name.startsWith("read")
                || name.startsWith("query") || name.startsWith("load") || name.startsWith("search");
    }

    /**
     * Enables call-site sink matching. By default Tai-e finds sinks via call-graph
     * edges into the sink method, which misses sinks declared on interface library
     * types with no concrete implementation on the classpath (e.g.
     * {@code HttpServletResponse.sendRedirect}). Call-site mode also matches by the
     * call site's resolved method reference, and still only reports when the
     * argument is actually tainted — so it adds recall without losing precision.
     */
    @Override
    protected boolean callSiteMode() {
        return true;
    }
}
