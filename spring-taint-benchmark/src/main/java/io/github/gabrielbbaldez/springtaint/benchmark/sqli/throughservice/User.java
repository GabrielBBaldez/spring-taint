package io.github.gabrielbbaldez.springtaint.benchmark.sqli.throughservice;

/** Minimal domain record for the through-service SQL injection case. */
public record User(long id, String name) {
}
