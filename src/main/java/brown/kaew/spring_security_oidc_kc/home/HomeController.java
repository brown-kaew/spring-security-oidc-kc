package brown.kaew.spring_security_oidc_kc.home;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {

    private static final Logger log = LoggerFactory.getLogger(HomeController.class);

    @GetMapping("/")
    public String home(Model model, Authentication authentication) {
        log.info("homepage");
        if (authentication.getPrincipal() instanceof OidcUser oidcUser) {
            model.addAttribute("user", oidcUser.getPreferredUsername());
        }
        return "home";
    }

    @GetMapping("/admin")
    public String admin(Model model, Authentication authentication) {
        log.info("Admin page accessed");
        if (authentication.getPrincipal() instanceof OidcUser oidcUser) {
            model.addAttribute("user", oidcUser.getPreferredUsername());
        }
        return "admin";
    }

    @GetMapping("/access_denied")
    public String accessDenied(Model model, Authentication authentication) {
        log.warn("Access denied page accessed");
        if (authentication.getPrincipal() instanceof OidcUser oidcUser) {
            model.addAttribute("user", oidcUser.getPreferredUsername());
        }
        return "access_denied";
    }
}
