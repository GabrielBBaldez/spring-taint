# Security Policy

## Reporting a vulnerability

Spring Taint Analyzer is a security tool, so we take its own security seriously.

If you find a vulnerability in this project, please report it privately:

- Use GitHub's **[private vulnerability reporting](https://github.com/GabrielBBaldez/spring-taint/security/advisories/new)**
  (Security → Report a vulnerability), or
- email the maintainer.

Please do **not** open a public issue for security problems.

Include, where possible: a description, affected version, reproduction steps, and
impact. You can expect an acknowledgement within a few days.

## Scope

This policy covers the analyzer, CLI, Docker image, and GitHub Action in this
repository. The `spring-taint-benchmark` module contains **intentionally vulnerable
code** for testing — that is by design and not a vulnerability in the tool.

## Supported versions

The latest released version receives fixes. This project is pre-1.0; APIs and
configuration may change between minor versions.
