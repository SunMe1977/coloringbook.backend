package com.hansjoerg.coloringbook.security.oauth2.user;

import com.hansjoerg.coloringbook.exception.OAuth2AuthenticationProcessingException;
import com.hansjoerg.coloringbook.model.AuthProvider;

import java.util.Map;

public class OAuth2UserInfoFactory {

    public static OAuth2UserInfo getOAuth2UserInfo(String registrationId, Map<String, Object> attributes) {
        if(registrationId.equalsIgnoreCase(AuthProvider.google.toString())) {
            return new GoogleOAuth2UserInfo(attributes);
        } else if (registrationId.equalsIgnoreCase(AuthProvider.facebook.toString())) {
            return new FacebookOAuth2UserInfo(attributes);
        } else if (registrationId.equalsIgnoreCase(AuthProvider.github.toString())) {
            return new GithubOAuth2UserInfo(attributes);
        } else {
            // Use message key and pass registrationId as argument
            throw new OAuth2AuthenticationProcessingException("error.oauth2.notSupported", registrationId);
        }
    }
}
