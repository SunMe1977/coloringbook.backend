package com.hansjoerg.coloringbook.security.oauth2;

import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class HttpCookieOAuth2AuthorizationRequestRepository implements AuthorizationRequestRepository<OAuth2AuthorizationRequest> {

    public static final String REDIRECT_URI_PARAM_SESSION_ATTRIBUTE = "redirect_uri";
    public static final String AUTH_REQUEST_SESSION_ATTRIBUTE = "oauth2_auth_request";

    @Override
    public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
        Object authRequest = request.getSession().getAttribute(AUTH_REQUEST_SESSION_ATTRIBUTE);
        if (authRequest instanceof OAuth2AuthorizationRequest) {
            return (OAuth2AuthorizationRequest) authRequest;
        }
        return null;
    }

    @Override
    public void saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest,
                                         HttpServletRequest request,
                                         HttpServletResponse response) {
        if (authorizationRequest != null) {
            request.getSession().setAttribute(AUTH_REQUEST_SESSION_ATTRIBUTE, authorizationRequest);
        }

        String redirectUriAfterLogin = request.getParameter(REDIRECT_URI_PARAM_SESSION_ATTRIBUTE);
        if (StringUtils.isNotBlank(redirectUriAfterLogin)) {
            request.getSession().setAttribute(REDIRECT_URI_PARAM_SESSION_ATTRIBUTE, redirectUriAfterLogin);
        }
    }

    @Override
    public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request,
                                                                 HttpServletResponse response) {
        OAuth2AuthorizationRequest removedRequest = loadAuthorizationRequest(request);
        request.getSession().removeAttribute(AUTH_REQUEST_SESSION_ATTRIBUTE);
        request.getSession().removeAttribute(REDIRECT_URI_PARAM_SESSION_ATTRIBUTE);
        return removedRequest;
    }
}
