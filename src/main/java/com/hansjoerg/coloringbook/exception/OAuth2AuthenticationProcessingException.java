package com.hansjoerg.coloringbook.exception;

import lombok.Getter;
import org.springframework.security.core.AuthenticationException;

@Getter
public class OAuth2AuthenticationProcessingException extends AuthenticationException {
    private final String messageKey;
    private final Object[] args;

    public OAuth2AuthenticationProcessingException(String messageKey, Object... args) {
        super(messageKey); // Call super with the key for internal logging/identification
        this.messageKey = messageKey;
        this.args = args;
    }

    // Original constructor for compatibility, will be updated in usage
    public OAuth2AuthenticationProcessingException(String msg, Throwable t) {
        this("error.oauth2.generic", new Object[]{msg}, t); // Use a generic key for now
    }

    public OAuth2AuthenticationProcessingException(String msg) {
        this("error.oauth2.generic", new Object[]{msg}); // Use a generic key for now
    }

    // New constructor to support message key and args with a cause
    public OAuth2AuthenticationProcessingException(String messageKey, Object[] args, Throwable t) {
        super(messageKey, t);
        this.messageKey = messageKey;
        this.args = args;
    }
}
