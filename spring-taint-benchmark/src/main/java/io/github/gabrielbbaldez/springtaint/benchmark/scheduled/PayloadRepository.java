package io.github.gabrielbbaldez.springtaint.benchmark.scheduled;

import org.springframework.stereotype.Repository;

/**
 * A repository whose read returns externally-originated data (persisted earlier from
 * untrusted input). Concrete so the entry-point modelling can resolve the call.
 */
@Repository
public class PayloadRepository {

    public String findLatestPayload() {
        return "stored-value";   // stands in for a database read
    }
}
