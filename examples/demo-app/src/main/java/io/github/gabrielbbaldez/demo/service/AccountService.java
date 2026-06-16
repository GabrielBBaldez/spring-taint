package io.github.gabrielbbaldez.demo.service;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

/** The service layer the SQL injection flows through. */
@Service
public class AccountService {

    private final JdbcTemplate jdbc;

    public AccountService(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /** VULNERABLE: owner concatenated into SQL. */
    public int deleteByOwner(String owner) {
        return jdbc.update("DELETE FROM accounts WHERE owner = '" + owner + "'");  // EXPECTED: sql-injection
    }

    /** SAFE: bound parameter — must NOT be flagged. */
    public int deleteByOwnerSafe(String owner) {
        return jdbc.update("DELETE FROM accounts WHERE owner = ?", owner);         // safe
    }
}
