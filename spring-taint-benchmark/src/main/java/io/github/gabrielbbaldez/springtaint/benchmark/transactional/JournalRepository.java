package io.github.gabrielbbaldez.springtaint.benchmark.transactional;

import org.springframework.stereotype.Repository;

/** A repository whose read returns previously-stored (untrusted) data. */
@Repository
public class JournalRepository {

    public void save(String entry) {
        // persist
    }

    public String findLatest() {
        return "stored";   // stands in for a read of a just-written row
    }
}
