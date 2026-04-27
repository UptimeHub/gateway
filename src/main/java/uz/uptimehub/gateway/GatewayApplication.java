package uz.uptimehub.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import uz.uptimehub.gateway.config.SecurityWhitelistProperties;

@EnableConfigurationProperties(SecurityWhitelistProperties.class)
@SpringBootApplication
public class GatewayApplication {

    static void main(String[] args) {
        SpringApplication.run(GatewayApplication.class, args);
    }

}
