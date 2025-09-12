package com.hansjoerg.coloringbook.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
@ConfigurationProperties(prefix = "app")
@Getter
public class AppProperties {

    private final Swagger swagger = new Swagger();
    private final Auth auth = new Auth();
    private final OAuth2 oauth2 = new OAuth2();
    private final Cors cors = new Cors();
    private final Frontend frontend = new Frontend();
    private final RateLimit rateLimit = new RateLimit(); // Added RateLimit properties


    @Setter
    @Getter
    public static class Swagger {
        private String password;
    }

    @Setter
    @Getter
    public static class Auth {
        private String tokenSecret;
        private long tokenExpirationMsec;
    }

    @Setter
    @Getter
    public static class Cors {
        private String allowedOrigins;
    }

    @Setter
    @Getter
    public static class Frontend {
        private String baseUrl;
    }

    @Setter
    @Getter
    public static class OAuth2 {
        private String redirectUri;
        private List<String> authorizedRedirectUris = new ArrayList<>();
    }

    @Setter
    @Getter
    public static class RateLimit {
        private double loginRps; // Requests per second for login
        private double signupRps; // Requests per second for signup
        private long cacheExpiryMinutes; // How long to keep IP rate limiters in cache
        private long maxCacheSize; // Max number of IP addresses to track
    }
}
