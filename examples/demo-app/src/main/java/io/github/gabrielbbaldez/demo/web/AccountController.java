package io.github.gabrielbbaldez.demo.web;

import io.github.gabrielbbaldez.demo.service.AccountService;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** SQL injection that crosses a layer: controller -> service -> JdbcTemplate. */
@RestController
public class AccountController {

    private final AccountService accounts;

    public AccountController(AccountService accounts) {
        this.accounts = accounts;
    }

    /** VULNERABLE: owner flows into a concatenated query one layer down. */
    @DeleteMapping("/accounts")
    public int delete(@RequestParam String owner) {
        return accounts.deleteByOwner(owner);                 // EXPECTED: sql-injection (cross-layer)
    }

    /** SAFE: the service uses a parameterized query — must NOT be flagged. */
    @DeleteMapping("/accounts-safe")
    public int deleteSafe(@RequestParam String owner) {
        return accounts.deleteByOwnerSafe(owner);
    }
}
