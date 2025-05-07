package brown.kaew.spring_security_oidc_kc.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class KcSecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/access_denied").permitAll()
                .requestMatchers("/**").hasAuthority("CLIENT_USER")
                .requestMatchers("/admin").hasAuthority("CLIENT_ADMIN")
                .anyRequest().denyAll()
        );

        http.oauth2Login(Customizer.withDefaults());

        http.exceptionHandling(exceptionHandling -> exceptionHandling
                .accessDeniedPage("/access_denied")
        );

        return http.build();
    }
}
