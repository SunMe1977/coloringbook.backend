package com.hansjoerg.coloringbook.security.oauth2;

import com.hansjoerg.coloringbook.config.AppProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class OAuth2AuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    private final AppProperties appProperties;

    @Autowired
    public OAuth2AuthenticationFailureHandler(AppProperties appProperties) {
        this.appProperties = appProperties;
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {

        String targetUrl = UriComponentsBuilder.fromUriString(appProperties.getOauth2().getRedirectUri())
                .queryParam("error", exception.getLocalizedMessage())
                .build()
                .toUriString();

        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }
}
