package io.github.gabrielbbaldez.springtaint.benchmark.sqli.threelayers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * SQL injection across FOUR layers: Controller -> Service -> Validator ->
 * Repository. Exercises deeper interprocedural propagation (and the depth of
 * field-object modelling for injected beans).
 *
 * <p>EXPECTED: sql-injection (CWE-89), cross-layer.
 */
@RestController
public class ThreeLayerController {

    private final ThreeLayerService service;

    public ThreeLayerController(ThreeLayerService service) {
        this.service = service;
    }

    @GetMapping("/users3/search")
    public List<String> search(@RequestParam String name) { // taint-source: @RequestParam name
        return service.search(name);
    }
}
