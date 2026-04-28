package uz.uptimehub.gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import reactor.core.publisher.Flux;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    private final SecurityWhitelistProperties properties;

    public SecurityConfig(SecurityWhitelistProperties securityWhitelistProperties) {
        this.properties = securityWhitelistProperties;
    }

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        String[] whitelist = properties.getWhitelist().toArray(String[]::new);

        http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(exchanges ->
                        exchanges
                                .pathMatchers(whitelist)
                                .permitAll()
                                .anyExchange()
                                .permitAll()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
                );
        return http.build();
    }

    @Bean
    public CorsWebFilter corsWebFilter() {
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        corsConfiguration.setAllowedOriginPatterns(List.of("*"));
        corsConfiguration.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        corsConfiguration.setAllowedHeaders(List.of("*"));
        corsConfiguration.setAllowCredentials(true);

        return new CorsWebFilter(new UrlBasedCorsConfigurationSource() {{
            registerCorsConfiguration("/**", corsConfiguration);
        }});
    }


    @Bean
    public ReactiveJwtAuthenticationConverter jwtAuthenticationConverter() {
        var converter = new ReactiveJwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(jwt -> Flux.fromIterable(extractAuthorities(jwt)));
        return converter;
    }

    private Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
        var defaultConverter = new JwtGrantedAuthoritiesConverter();

        Collection<GrantedAuthority> authorities =
                new ArrayList<>(defaultConverter.convert(jwt));

        Map<String, Object> resourceAccess = jwt.getClaim("resource_access");

        addClientRoles(authorities, resourceAccess, "main-client", "ROLE_");
        addClientRoles(authorities, resourceAccess, "account", "");

        return authorities;
    }

    private void addClientRoles(
            Collection<GrantedAuthority> authorities,
            Map<String, Object> resourceAccess,
            String clientName,
            String prefix
    ) {
        if (resourceAccess == null) return;

        Object clientAccessObj = resourceAccess.get(clientName);

        if (!(clientAccessObj instanceof Map<?, ?> clientAccess)) {
            return;
        }

        Object rolesObj = clientAccess.get("roles");

        if (!(rolesObj instanceof Collection<?> roles)) return;

        roles.stream()
                .filter(String.class::isInstance)
                .map(String.class::cast)
                .map(role -> new SimpleGrantedAuthority(prefix + role))
                .forEach(authorities::add);
    }
}
