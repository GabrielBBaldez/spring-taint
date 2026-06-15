package io.github.gabrielbbaldez.springtaint.config;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * A sanitizer in Tai-e's native format: taint is cleared at the given position.
 *
 * @param method Tai-e method signature, {@code <Class: ReturnType name(ParamTypes)>}
 * @param index  position whose taint is cleared: {@code result} or a parameter index
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record SanitizerSpec(String method, String index) {
}
