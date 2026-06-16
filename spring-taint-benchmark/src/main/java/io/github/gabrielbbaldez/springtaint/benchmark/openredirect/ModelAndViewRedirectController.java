package io.github.gabrielbbaldez.springtaint.benchmark.openredirect;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

/**
 * Open redirect via a Spring MVC view name. A {@code "redirect:"} view name built
 * from user input lets an attacker choose the redirect target. Tools that only
 * model {@code HttpServletResponse.sendRedirect} miss this very common pattern.
 *
 * <p>EXPECTED: open-redirect (CWE-601). Source: @RequestParam; sink:
 * ModelAndView.setViewName.
 */
@RestController
public class ModelAndViewRedirectController {

    @GetMapping("/login-redirect")
    public ModelAndView login(@RequestParam String returnUrl) {     // taint-source: @RequestParam returnUrl
        ModelAndView mv = new ModelAndView();
        mv.setViewName("redirect:" + returnUrl);                     // taint-sink: ModelAndView.setViewName -> EXPECTED open-redirect
        return mv;
    }
}
