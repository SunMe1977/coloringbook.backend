package com.hansjoerg.coloringbook.config;

import com.hansjoerg.coloringbook.security.*;
import com.hansjoerg.coloringbook.security.filter.JsonUsernamePasswordAuthenticationFilter;
import com.hansjoerg.coloringbook.security.oauth2.*;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
public class SecurityConfig {

    private final AppProperties appProperties;
    private final CustomUserDetailsService customUserDetailsService;
    private final CustomOAuth2UserService customOAuth2UserService;
    private final OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;
    private final OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler;
    private final HttpCookieOAuth2AuthorizationRequestRepository httpCookieOAuth2AuthorizationRequestRepository;
    private final TokenProvider tokenProvider;

    public SecurityConfig(AppProperties appProperties,
                          CustomUserDetailsService customUserDetailsService,
                          CustomOAuth2UserService customOAuth2UserService,
                          OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler,
                          OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler,
                          HttpCookieOAuth2AuthorizationRequestRepository httpCookieOAuth2AuthorizationRequestRepository,
                          TokenProvider tokenProvider) {
        this.appProperties = appProperties;
        this.customUserDetailsService = customUserDetailsService;
        this.customOAuth2UserService = customOAuth2UserService;
        this.oAuth2AuthenticationSuccessHandler = oAuth2AuthenticationSuccessHandler;
        this.oAuth2AuthenticationFailureHandler = oAuth2AuthenticationFailureHandler;
        this.httpCookieOAuth2AuthorizationRequestRepository = httpCookieOAuth2AuthorizationRequestRepository;
        this.tokenProvider = tokenProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public TokenAuthenticationFilter tokenAuthenticationFilter() {
        return new TokenAuthenticationFilter(tokenProvider, customUserDetailsService);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, AuthenticationManager authenticationManager) throws Exception {
        JsonUsernamePasswordAuthenticationFilter jsonLoginFilter = new JsonUsernamePasswordAuthenticationFilter();
        jsonLoginFilter.setAuthenticationManager(authenticationManager);
        jsonLoginFilter.setFilterProcessesUrl("/auth/login");
        jsonLoginFilter.setAuthenticationSuccessHandler((request, response, authentication) -> {
            String token = tokenProvider.createToken(authentication);
            String redirectUri = appProperties.getOauth2().getAuthorizedRedirectUris().get(0);
            String redirectUrl = redirectUri + "?token=" + token;
            response.sendRedirect(redirectUrl);
        });
        jsonLoginFilter.setAuthenticationFailureHandler((request, response, exception) -> {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("Login failed: " + exception.getMessage());
        });

        http
                .cors(withDefaults())
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .httpBasic(AbstractHttpConfigurer::disable)
                .exceptionHandling(ex -> ex.authenticationEntryPoint(new RestAuthenticationEntryPoint()))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/auth/**", "/oauth2/**", "/").permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2Login(oauth2 -> oauth2
                        .authorizationEndpoint(authorization -> authorization
                                .baseUri("/oauth2/authorize")
                                .authorizationRequestRepository(httpCookieOAuth2AuthorizationRequestRepository)
                        )
                        .redirectionEndpoint(redirection -> redirection
                                .baseUri("/oauth2/callback/google")
                        )
                        .userInfoEndpoint(userInfo -> userInfo
                                .userService(customOAuth2UserService)
                        )
                        .successHandler(oAuth2AuthenticationSuccessHandler)
                        .failureHandler(oAuth2AuthenticationFailureHandler)
                )
                .authenticationProvider(authenticationProvider())
                .addFilterBefore(jsonLoginFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(tokenAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(customUserDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
