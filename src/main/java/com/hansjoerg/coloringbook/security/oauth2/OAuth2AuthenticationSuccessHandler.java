package com.hansjoerg.coloringbook.security.oauth2;

import com.hansjoerg.coloringbook.config.AppProperties;
import com.hansjoerg.coloringbook.security.TokenProvider;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

@Component
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final TokenProvider tokenProvider;
    private final AppProperties appProperties;

    public OAuth2AuthenticationSuccessHandler(TokenProvider tokenProvider, AppProperties appProperties) {
        this.tokenProvider = tokenProvider;
        this.appProperties = appProperties;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        String token = tokenProvider.createToken(authentication);

        String redirectUri = appProperties.getOauth2().getAuthorizedRedirectUris().get(0);
        String targetUrl = UriComponentsBuilder.fromUriString(redirectUri)
                .queryParam("token", token)
                .build()
                .toUriString();

        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }
}
