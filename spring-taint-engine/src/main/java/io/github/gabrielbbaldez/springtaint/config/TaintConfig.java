package io.github.gabrielbbaldez.springtaint.config;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * The taint configuration: Spring source annotations plus concrete library
 * sources, sinks and sanitizers.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record TaintConfig(
        @JsonProperty("spring-sources") List<SpringSource> springSources,
        List<SourceSpec> sources,
        List<SinkSpec> sinks,
        List<SanitizerSpec> sanitizers) {

    public TaintConfig {
        springSources = (springSources == null) ? List.of() : List.copyOf(springSources);
        sources = (sources == null) ? List.of() : List.copyOf(sources);
        sinks = (sinks == null) ? List.of() : List.copyOf(sinks);
        sanitizers = (sanitizers == null) ? List.of() : List.copyOf(sanitizers);
    }
}
