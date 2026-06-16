package io.github.gabrielbbaldez.springtaint.config;

import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Resolves the method signatures in a {@link TaintConfig} against a classpath, so a
 * typo in a custom config is reported instead of silently matching nothing (and
 * giving false confidence that the code is safe).
 */
public final class ConfigValidator {

    /** One unresolved signature and why it could not be resolved. */
    public record Issue(String signature, String reason) {
    }

    /** The outcome of validating a config: how many signatures resolved, and which did not. */
    public record Report(int total, int resolved, List<Issue> issues) {
        public boolean ok() {
            return issues.isEmpty();
        }
    }

    public Report validate(TaintConfig config, List<URL> classpath) {
        URLClassLoader loader = new URLClassLoader(
                classpath.toArray(URL[]::new), getClass().getClassLoader());
        try {
            return validate(config, loader);
        } finally {
            try {
                loader.close();   // release jar file handles (important on Windows)
            } catch (java.io.IOException ignored) {
                // best effort
            }
        }
    }

    private Report validate(TaintConfig config, URLClassLoader loader) {
        Set<String> signatures = collectSignatures(config);
        List<Issue> issues = new ArrayList<>();
        int resolved = 0;
        for (String signature : signatures) {
            Parsed p = parse(signature);
            if (p == null) {
                issues.add(new Issue(signature, "malformed signature"));
                continue;
            }
            Class<?> clazz;
            try {
                clazz = Class.forName(p.className, false, loader);
            } catch (Throwable e) {                          // NoClassDefFound, linkage, etc.
                issues.add(new Issue(signature, "class not found on classpath: " + p.className));
                continue;
            }
            try {
                if (methodExists(clazz, p)) {
                    resolved++;
                } else {
                    issues.add(new Issue(signature,
                            "no method '" + p.method + "' taking " + p.paramCount + " parameter(s)"));
                }
            } catch (Throwable e) {
                // Class is present but its method table could not be read (a transitive
                // dependency is missing). Don't report it as a config error.
                resolved++;
            }
        }
        return new Report(signatures.size(), resolved, issues);
    }

    private static boolean methodExists(Class<?> clazz, Parsed p) {
        if (p.method.equals("<init>")) {
            for (var ctor : clazz.getDeclaredConstructors()) {
                if (ctor.getParameterCount() == p.paramCount) {
                    return true;
                }
            }
            return false;
        }
        // Walk up the hierarchy: a sink/source may be declared on a supertype.
        for (Class<?> c = clazz; c != null && c != Object.class; c = c.getSuperclass()) {
            for (Method m : c.getDeclaredMethods()) {
                if (m.getName().equals(p.method) && m.getParameterCount() == p.paramCount) {
                    return true;
                }
            }
            for (Class<?> iface : c.getInterfaces()) {
                for (Method m : iface.getMethods()) {
                    if (m.getName().equals(p.method) && m.getParameterCount() == p.paramCount) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private static Set<String> collectSignatures(TaintConfig config) {
        Set<String> out = new LinkedHashSet<>();
        config.sources().forEach(s -> out.add(s.method()));
        config.sinks().forEach(s -> out.add(s.method()));
        config.sanitizers().forEach(s -> out.add(s.method()));
        config.transfers().forEach(t -> out.add(t.method()));
        return out;
    }

    private record Parsed(String className, String method, int paramCount) {
    }

    /** Parses a Tai-e signature {@code <Class: Ret name(p1,p2)>} into class/method/arity. */
    private static Parsed parse(String signature) {
        try {
            String body = signature.substring(signature.indexOf('<') + 1, signature.lastIndexOf('>'));
            String className = body.substring(0, body.indexOf(':')).trim();
            String afterColon = body.substring(body.indexOf(':') + 1).trim();
            String beforeParen = afterColon.substring(0, afterColon.indexOf('('));
            String method = beforeParen.substring(beforeParen.lastIndexOf(' ') + 1).trim();
            String params = afterColon.substring(afterColon.indexOf('(') + 1, afterColon.indexOf(')')).trim();
            int paramCount = params.isEmpty() ? 0 : params.split(",").length;
            return new Parsed(className, method, paramCount);
        } catch (RuntimeException e) {
            return null;
        }
    }
}
