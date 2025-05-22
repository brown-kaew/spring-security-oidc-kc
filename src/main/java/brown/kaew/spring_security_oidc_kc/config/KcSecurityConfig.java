package brown.kaew.spring_security_oidc_kc.config;

import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.PathNotFoundException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import java.text.ParseException;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration.ProviderDetails;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StringUtils;

@Slf4j
@Configuration
@EnableWebSecurity
public class KcSecurityConfig {

    final ClientRegistrationRepository clientRegistrationRepository;

    public KcSecurityConfig(ClientRegistrationRepository clientRegistrationRepository) {
        this.clientRegistrationRepository = clientRegistrationRepository;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/access_denied").permitAll()
                .requestMatchers("/").hasAnyAuthority("CLIENT_USER", "CLIENT_ADMIN")
                .requestMatchers("/admin").hasAuthority("CLIENT_ADMIN")
                .anyRequest().authenticated()
        );

        http.oauth2Login(httpSecurityOAuth2LoginConfigurer -> httpSecurityOAuth2LoginConfigurer
                .userInfoEndpoint(userInfoEndpointConfig -> userInfoEndpointConfig
                        .oidcUserService(this.oidcUserService())
                )
        );

        http.logout(logout -> logout
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                .logoutSuccessHandler(oidcLogoutSuccessHandler())
        );

        http.exceptionHandling(exceptionHandling -> exceptionHandling
                .accessDeniedPage("/access_denied")
        );

        return http.build();
    }

    private OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
        final OidcUserService delegate = new OidcUserService();

        return (userRequest) -> {
            // Delegate to the default implementation for loading a user
            OidcUser oidcUser = delegate.loadUser(userRequest);

            OAuth2AccessToken accessToken = userRequest.getAccessToken();
            Set<GrantedAuthority> mappedAuthorities = new HashSet<>(oidcUser.getAuthorities());

            try {
                // 1) Fetch the authority information from the protected resource using accessToken
                JWTClaimsSet jwtClaimsSet = JWTParser.parse(accessToken.getTokenValue()).getJWTClaimsSet();
                // 2) Map the authority information to one or more GrantedAuthority's and add it to mappedAuthorities
                mappedAuthorities.addAll(extractAuthorities(jwtClaimsSet.getClaims()));
            } catch (ParseException e) {
                log.error("Failed to parse JWT claims set", e);
            }

            // 3) Create a copy of oidcUser but use the mappedAuthorities instead
            ProviderDetails providerDetails = userRequest.getClientRegistration().getProviderDetails();
            String userNameAttributeName = providerDetails.getUserInfoEndpoint().getUserNameAttributeName();
            if (StringUtils.hasText(userNameAttributeName)) {
                oidcUser = new DefaultOidcUser(mappedAuthorities, oidcUser.getIdToken(), oidcUser.getUserInfo(),
                        userNameAttributeName);
            } else {
                oidcUser = new DefaultOidcUser(mappedAuthorities, oidcUser.getIdToken(), oidcUser.getUserInfo());
            }

            return oidcUser;
        };
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    private static Collection<GrantedAuthority> extractAuthorities(Map<String, Object> claims) {
        /* See resource server solution above for authorities mapping */
        return Stream.of("$.realm_access.roles", "$.resource_access.*.roles").flatMap(claimPaths -> {
                    Object claim;
                    try {
                        claim = JsonPath.read(claims, claimPaths);
                    } catch (PathNotFoundException e) {
                        claim = null;
                    }
                    if (claim == null) {
                        return Stream.empty();
                    }
                    if (claim instanceof String claimStr) {
                        return Stream.of(claimStr.split(","));
                    }
                    if (claim instanceof String[] claimArr) {
                        return Stream.of(claimArr);
                    }
                    if (Collection.class.isAssignableFrom(claim.getClass())) {
                        final var iter = ((Collection) claim).iterator();
                        if (!iter.hasNext()) {
                            return Stream.empty();
                        }
                        final var firstItem = iter.next();
                        if (firstItem instanceof String) {
                            return (Stream<String>) ((Collection) claim).stream();
                        }
                        if (Collection.class.isAssignableFrom(firstItem.getClass())) {
                            return (Stream<String>) ((Collection) claim).stream()
                                    .flatMap(colItem -> ((Collection) colItem).stream()).map(String.class::cast);
                        }
                    }
                    return Stream.empty();
                })
                /* Insert some transformation here if you want to add a prefix like "ROLE_" or force upper-case authorities */
                .map(SimpleGrantedAuthority::new)
                .map(GrantedAuthority.class::cast).toList();
    }

    private LogoutSuccessHandler oidcLogoutSuccessHandler() {
        OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler =
                new OidcClientInitiatedLogoutSuccessHandler(this.clientRegistrationRepository);

        // Sets the location that the End-User's User Agent will be redirected to
        // after the logout has been performed at the Provider
        oidcLogoutSuccessHandler.setPostLogoutRedirectUri("{baseUrl}/");

        return oidcLogoutSuccessHandler;
    }
}
