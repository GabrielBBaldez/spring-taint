package io.github.gabrielbbaldez.springtaint.engine.taie;

import pascal.taie.language.classes.JMethod;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Shared logic for recognising Spring entry points and their tainted parameters.
 * Used by both {@link SpringEntryPointPlugin} (to add entry points) and
 * {@link SpringTaintConfigProvider} (to emit param sources), so the two always
 * agree on the same methods and parameters.
 */
final class SpringSources {

    /** Annotations carried by the parameter itself; that parameter is tainted. */
    static final Set<String> PARAM_ANNOTATIONS = Set.of(
            "org.springframework.web.bind.annotation.RequestParam",
            "org.springframework.web.bind.annotation.PathVariable",
            "org.springframework.web.bind.annotation.RequestBody",
            "org.springframework.web.bind.annotation.RequestHeader",
            "org.springframework.web.bind.annotation.CookieValue",
            "org.springframework.web.bind.annotation.ModelAttribute");

    /** Annotations carried by the method; all of its parameters are external input. */
    static final Set<String> METHOD_ANNOTATIONS = Set.of(
            "org.springframework.kafka.annotation.KafkaListener");

    private SpringSources() {
    }

    /** Parameter indices of {@code m} that are taint sources, or empty if none. */
    static List<Integer> taintedParams(JMethod m) {
        List<Integer> result = new ArrayList<>();
        boolean methodIsSource = METHOD_ANNOTATIONS.stream().anyMatch(m::hasAnnotation);
        for (int i = 0; i < m.getParamCount(); i++) {
            if (methodIsSource || hasAnyParamAnnotation(m, i)) {
                result.add(i);
            }
        }
        return result;
    }

    /** Whether {@code m} is a Spring entry point (has at least one tainted parameter). */
    static boolean isEntry(JMethod m) {
        return !m.isAbstract() && !taintedParams(m).isEmpty();
    }

    private static boolean hasAnyParamAnnotation(JMethod m, int i) {
        for (String anno : PARAM_ANNOTATIONS) {
            if (m.hasParamAnnotation(i, anno)) {
                return true;
            }
        }
        return false;
    }
}
