package io.github.gabrielbbaldez.springtaint.config;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * A concrete-method taint source in Tai-e's native format.
 *
 * @param kind   {@code call} (return value tainted) or {@code param} (parameter tainted)
 * @param method Tai-e method signature, {@code <Class: ReturnType name(ParamTypes)>}
 * @param index  tainted position: {@code result} or a parameter index
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record SourceSpec(String kind, String method, String index) {
}
