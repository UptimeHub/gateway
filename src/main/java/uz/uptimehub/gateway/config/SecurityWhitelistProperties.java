package uz.uptimehub.gateway.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

@ConfigurationProperties(prefix = "security-filter")
public class SecurityWhitelistProperties {
    private final List<String> whitelist = new ArrayList<>();

    public List<String> getWhitelist() {
        return whitelist;
    }
}
