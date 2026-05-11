package uz.uptimehub.gateway.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.OAuthFlow;
import io.swagger.v3.oas.annotations.security.OAuthFlows;
import io.swagger.v3.oas.annotations.security.OAuthScope;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.annotations.servers.Server;
import org.springframework.context.annotation.Configuration;

@Configuration
@OpenAPIDefinition(
        info = @Info(title = "UptimeHub API", version = "1.0"),
        servers = @Server(url = "http://localhost:8899", description = "Local Server"),
        security = @SecurityRequirement(name = "Keycloak")
)
@SecurityScheme(
        name = "Keycloak",
        type = SecuritySchemeType.OAUTH2,
        flows = @OAuthFlows(
                authorizationCode = @OAuthFlow(
                        authorizationUrl = "http://localhost:8080/realms/booking-system/protocol/openid-connect/auth",
                        tokenUrl = "http://localhost:8080/realms/booking-system/protocol/openid-connect/token",
                        scopes = {
                                @OAuthScope(name = "openid", description = "OpenID Connect scope"),
                                @OAuthScope(name = "profile", description = "User profile"),
                                @OAuthScope(name = "email", description = "User email")
                        }
                )
        )
)
public class SwaggerConfig {
}