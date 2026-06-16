package io.github.gabrielbbaldez.springtaint.benchmark.misconfig;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Insecure Spring Security configuration: CSRF protection and the clickjacking
 * (X-Frame-Options) defence are both turned off. Input for `spring-taint misconfig`.
 *
 * <p>EXPECTED: insecure-config (CSRF disabled, frame options disabled).
 */
@Configuration
public class InsecureSecurityConfig {

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable());                       // misconfig: CSRF protection removed
        http.headers(headers -> headers.frameOptions(frame -> frame.disable())); // misconfig: clickjacking defence off
        return http.build();
    }
}
