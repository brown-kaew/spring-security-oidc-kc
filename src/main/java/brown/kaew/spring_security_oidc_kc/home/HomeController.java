package brown.kaew.spring_security_oidc_kc.home;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {

    private static final Logger log = LoggerFactory.getLogger(HomeController.class);

    @GetMapping("/")
    public String home() {
        log.info("homepage");
        return "home";
    }

    @GetMapping("/admin")
    public String admin() {
        log.info("Admin page accessed");
        return "admin";
    }

    @GetMapping("/access_denied")
    public String accessDenied() {
        log.warn("Access denied page accessed");
        return "access_denied";
    }
}
