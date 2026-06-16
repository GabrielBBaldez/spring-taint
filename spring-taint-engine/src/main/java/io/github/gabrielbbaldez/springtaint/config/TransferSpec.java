package io.github.gabrielbbaldez.springtaint.config;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * A taint transfer in Tai-e's native format: taint moves from one position to
 * another at calls of {@code method}. Used to model containers and persistence
 * (e.g. a repository {@code save} stores taint on the repo; {@code find} loads it
 * back out).
 *
 * @param method Tai-e method signature, {@code <Class: ReturnType name(ParamTypes)>}
 * @param from   source position: a parameter index, {@code base}, or {@code result}
 * @param to     destination position: a parameter index, {@code base}, or {@code result}
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record TransferSpec(String method, String from, String to) {
}
