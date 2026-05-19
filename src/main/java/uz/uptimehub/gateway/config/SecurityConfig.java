package uz.uptimehub.gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
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

import java.util.*;

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

                                // Core endpoints
                                .pathMatchers("/api/core/admin-user/**").hasRole("PLATFORM_ADMIN")
                                .pathMatchers("/api/core/organization/detailed/**").hasAnyRole("PLATFORM_ADMIN", "ORGANIZATION_ADMIN")
                                .pathMatchers(HttpMethod.PATCH, "/api/core/organiztion/**").hasRole("ORGANIZATION_ADMIN")
                                .pathMatchers(HttpMethod.POST, "/api/core/provider-type/**").hasRole("PLATFORM_ADMIN")
                                .pathMatchers(HttpMethod.PATCH, "/api/core/provider-type/**").hasRole("PLATFORM_ADMIN")
                                .pathMatchers(HttpMethod.GET, "/api/core/provider-type/**").permitAll()

                                // Resource endpoints
                                .pathMatchers(HttpMethod.POST, "/api/resource/category/**").hasRole("PLATFORM_ADMIN")
                                .pathMatchers(HttpMethod.PATCH, "/api/resource/category/**").hasRole("PLATFORM_ADMIN")
                                .pathMatchers(HttpMethod.GET, "/api/resource/category/**").permitAll()
                                .anyExchange()
                                .authenticated()
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

        converter.setJwtGrantedAuthoritiesConverter(jwt ->
                Flux.fromIterable(extractAuthorities(jwt))
        );

        return converter;
    }

    private Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {

        var defaultConverter = new JwtGrantedAuthoritiesConverter();
        Collection<GrantedAuthority> defaultAuthorities = defaultConverter.convert(jwt);

        Set<GrantedAuthority> authorities = new HashSet<>(defaultAuthorities);

        addRealmRoles(authorities, jwt);
        addPermissions(authorities, jwt);

        return authorities;
    }

    private void addRealmRoles(Collection<GrantedAuthority> authorities, Jwt jwt) {
        Map<String, Object> realmAccess = jwt.getClaim("realm_access");

        if (realmAccess == null) {
            return;
        }

        Object rolesObj = realmAccess.get("roles");

        if (!(rolesObj instanceof Collection<?> roles)) {
            return;
        }

        roles.stream()
                .filter(String.class::isInstance)
                .map(String.class::cast)
                .map(String::trim)
                .filter(role -> !role.isBlank())
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .forEach(authorities::add);
    }

    private void addPermissions(Collection<GrantedAuthority> authorities, Jwt jwt) {
        Object permissionsObj = jwt.getClaim("permissions");

        if (!(permissionsObj instanceof Collection<?> permissions)) {
            return;
        }

        permissions.stream()
                .filter(String.class::isInstance)
                .map(String.class::cast)
                .map(String::trim)
                .filter(permission -> !permission.isBlank())
                .map(SimpleGrantedAuthority::new)
                .forEach(authorities::add);
    }
}
