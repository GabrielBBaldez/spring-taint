package io.github.gabrielbbaldez.springtaint.config;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * A taint transfer in Tai-e's native format: taint moves from one position to
 * another at calls of {@code method}. Used to model containers and persistence
 * (e.g. a repository {@code save} stores taint on the repo; {@code find} loads it
 * back out) and transparent wrappers (Optional, CompletableFuture).
 *
 * @param method Tai-e method signature, {@code <Class: ReturnType name(ParamTypes)>}
 * @param from   source position: a parameter index, {@code base}, or {@code result}
 * @param to     destination position: a parameter index, {@code base}, or {@code result}
 * @param type   optional type of the transferred taint object. Defaults to the
 *               declared type of {@code to}. Set it (e.g. {@code java.lang.String})
 *               when an {@code Object}-returning unwrap is immediately cast: Tai-e
 *               type-filters at the cast, so an {@code Object}-typed taint would be
 *               dropped, whereas a {@code String}-typed one survives the cast.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record TransferSpec(String method, String from, String to, String type) {
}
