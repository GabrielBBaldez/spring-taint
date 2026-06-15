package io.github.gabrielbbaldez.springtaint.config;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * A taint sink in Tai-e's native format.
 *
 * @param vuln   vulnerability category reported when tainted data reaches this sink
 * @param method Tai-e method signature, {@code <Class: ReturnType name(ParamTypes)>}
 * @param index  parameter index that must not receive tainted data
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record SinkSpec(String vuln, String method, String index) {
}
