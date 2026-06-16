package io.github.gabrielbbaldez.springtaint.benchmark.feign;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

/**
 * A Feign client to a downstream service. Values it returns originate outside this
 * application and are untrusted at the caller — a source that tools treating Feign
 * results as clean data will miss.
 */
@FeignClient(name = "user-service", url = "http://users")
public interface UserClient {

    @GetMapping("/users/{id}/name")
    String getUserName(@PathVariable("id") String id);   // returns external service data
}
