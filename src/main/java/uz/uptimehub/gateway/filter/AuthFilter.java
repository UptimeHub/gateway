package uz.uptimehub.gateway.filter;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Collection;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

@Configuration
public class AuthFilter implements GlobalFilter, Ordered {
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .filter(Objects::nonNull)
                .flatMap(auth -> {
                    if (!(auth.getPrincipal() instanceof Jwt principal)) {
                        return chain.filter(exchange);
                    }

                    String userId = principal.getSubject();
                    String organizationId = principal.getClaimAsString("organization_id");

                    String roles = extractRealmRoles(principal);
                    String permissions = extractPermissions(principal);

                    ServerHttpRequest.Builder requestBuilder = exchange.getRequest()
                            .mutate()
                            // remove possibly spoofed incoming headers
                            .headers(headers -> {
                                headers.remove("X-User-Id");
                                headers.remove("X-Organization-Id");
                                headers.remove("X-Auth-Roles");
                                headers.remove("X-Auth-Permissions");
                            })
                            // add trusted headers
                            .header("X-User-Id", userId)
                            .header("X-Auth-Roles", roles)
                            .header("X-Auth-Permissions", permissions);

                    if (organizationId != null && !organizationId.isBlank()) {
                        requestBuilder.header("X-Organization-Id", organizationId);
                    }

                    ServerHttpRequest mutatedRequest = requestBuilder.build();

                    return chain.filter(
                            exchange.mutate()
                                    .request(mutatedRequest)
                                    .build()
                    );
                })
                .switchIfEmpty(chain.filter(exchange));
    }

    @Override
    public int getOrder() {
        return Ordered.LOWEST_PRECEDENCE;
    }

    private String extractRealmRoles(Jwt jwt) {
        Map<String, Object> realmAccess = jwt.getClaim("realm_access");

        if (realmAccess == null) {
            return "";
        }

        Object rolesObj = realmAccess.get("roles");

        if (!(rolesObj instanceof Collection<?> roles)) {
            return "";
        }

        return roles.stream()
                .filter(String.class::isInstance)
                .map(String.class::cast)
                .map(String::trim)
                .filter(role -> !role.isBlank())
                // optional: skip Keycloak default roles
                .filter(role -> !role.equals("offline_access"))
                .filter(role -> !role.equals("uma_authorization"))
                .filter(role -> !role.startsWith("default-roles-"))
                .distinct()
                .collect(Collectors.joining(","));
    }

    private String extractPermissions(Jwt jwt) {
        Object permissionsObj = jwt.getClaim("permissions");

        if (!(permissionsObj instanceof Collection<?> permissions)) {
            return "";
        }

        return permissions.stream()
                .filter(String.class::isInstance)
                .map(String.class::cast)
                .map(String::trim)
                .filter(permission -> !permission.isBlank())
                .distinct()
                .collect(Collectors.joining(","));
    }
}
