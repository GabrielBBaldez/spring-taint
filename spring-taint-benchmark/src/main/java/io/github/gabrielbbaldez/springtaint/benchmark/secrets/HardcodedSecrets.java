package io.github.gabrielbbaldez.springtaint.benchmark.secrets;

import org.springframework.beans.factory.annotation.Value;

/**
 * Intentionally hardcoded secrets, for the {@code secrets} scanner.
 *
 * <p>EXPECTED: hardcoded-secret findings for DB_PASSWORD, AWS_ACCESS_KEY, the
 * {@code @Value} API-key default, and the inline token. {@code timeout} is safe.
 */
public class HardcodedSecrets {

    // secret-named constant
    private static final String DB_PASSWORD = "admin123";          // taint-sink: hardcoded-secret

    // recognizable secret format (AWS access key id)
    private static final String AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"; // taint-sink: hardcoded-secret

    // hardcoded default for an externalized property
    @Value("${api.key:sk-1a2b3c4d5e6f7g8h}")                       // taint-sink: hardcoded-secret
    private String apiKey;

    // safe: not a secret, no secret-like default
    @Value("${app.timeout:30}")
    private int timeout;

    public String inlineToken() {
        return "ghp_abcdef0123456789ABCDEF0123456789";             // taint-sink: hardcoded-secret
    }

    public int timeout() {
        return timeout;
    }
}
