package io.github.gabrielbbaldez.springtaint.config;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * A Spring annotation that marks an external entry point. The engine's Spring
 * layer discovers methods (or parameters) carrying this annotation and emits a
 * Tai-e {@code param} source for each, because annotation-driven entry points
 * have no explicit call site.
 *
 * @param annotation fully-qualified annotation type, e.g.
 *                   {@code org.springframework.web.bind.annotation.RequestParam}
 * @param note       optional human note
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record SpringSource(String annotation, String note) {
}
