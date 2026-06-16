package io.github.gabrielbbaldez.springtaint.config;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.stream.Stream;

/**
 * The taint configuration: Spring source annotations plus concrete library
 * sources, sinks and sanitizers.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record TaintConfig(
        @JsonProperty("spring-sources") List<SpringSource> springSources,
        List<SourceSpec> sources,
        List<SinkSpec> sinks,
        List<SanitizerSpec> sanitizers,
        List<TransferSpec> transfers) {

    public TaintConfig {
        springSources = (springSources == null) ? List.of() : List.copyOf(springSources);
        sources = (sources == null) ? List.of() : List.copyOf(sources);
        sinks = (sinks == null) ? List.of() : List.copyOf(sinks);
        sanitizers = (sanitizers == null) ? List.of() : List.copyOf(sanitizers);
        transfers = (transfers == null) ? List.of() : List.copyOf(transfers);
    }

    /** Returns a new config that is the union of this config and {@code other}. */
    public TaintConfig mergeWith(TaintConfig other) {
        return new TaintConfig(
                union(springSources, other.springSources),
                union(sources, other.sources),
                union(sinks, other.sinks),
                union(sanitizers, other.sanitizers),
                union(transfers, other.transfers));
    }

    private static <T> List<T> union(List<T> a, List<T> b) {
        return Stream.concat(a.stream(), b.stream()).distinct().toList();
    }
}
