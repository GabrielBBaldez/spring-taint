# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
[Semantic Versioning](https://semver.org/).

## [0.5.0] - 2026-06-16

### Added
- **Hardcoded-secrets scanner** — `spring-taint secrets <classes>`: a bytecode
  pattern scan (any JDK) for secret-named constants, known key formats (AWS,
  GitHub, Slack, PEM, …), and `@Value` defaults. Reported values are masked.
- **Web dashboard** (`dashboard/`, React + Vite + TypeScript) for exploring SARIF
  reports, including the full source→sink taint flow per finding.
- `--config` is now **merged** onto the built-in rules; `--no-default-config`
  restores replace behavior. The config gains a `transfers` section.

### Changed
- Relicensed to **MIT**. Added CONTRIBUTING, CODE_OF_CONDUCT, SECURITY, and
  GitHub issue/PR templates.

## [0.4.0] - 2026-06-16

### Added
- **Stored / second-order injection.** Data returned by a `@Repository` read method
  (returning `String`) is treated as untrusted, catching cross-request flows (e.g.
  stored XSS saved by one request and rendered by another). Conservative by design.
- A `transfers` section in the taint configuration (Tai-e taint transfers).

### Changed
- Benchmark grows to 20 cases (17 vulnerable, 3 safe); engine detects **17/17** with
  0 false positives.

## [0.3.0] - 2026-06-15

### Added
- Multi-framework sources: JAX-RS / Quarkus (`@QueryParam`, `@PathParam`, …) and
  Micronaut (`@QueryValue`, `@Body`, …), alongside Spring MVC/WebFlux and Kafka.
- Per-rule reference documentation (`docs/rules.md`).

## [0.2.0] - 2026-06-15

### Added
- Sources: `@PathVariable`, `@RequestBody`, `@RequestHeader`.
- Reactive WebFlux / R2DBC SQL injection via `DatabaseClient` (interface sink
  matched through call-site mode).
- A self-contained executable jar with the default config bundled.

## [0.1.0] - 2026-06-15

### Added
- Initial working release: interprocedural taint analysis for Spring Boot on Tai-e.
- Detects SQL injection (direct, cross-layer, via `@KafkaListener`), reflected and
  conditional-sanitizer XSS, SSRF, SpEL injection, path traversal, command injection,
  and open redirect.
- CLI with SARIF 2.1 output, a Docker-based GitHub Action, and a benchmark with
  documented ground truth.

[0.5.0]: https://github.com/GabrielBBaldez/spring-taint/releases/tag/v0.5.0
[0.4.0]: https://github.com/GabrielBBaldez/spring-taint/releases/tag/v0.4.0
[0.3.0]: https://github.com/GabrielBBaldez/spring-taint/releases/tag/v0.3.0
[0.2.0]: https://github.com/GabrielBBaldez/spring-taint/releases/tag/v0.2.0
[0.1.0]: https://github.com/GabrielBBaldez/spring-taint/releases/tag/v0.1.0
