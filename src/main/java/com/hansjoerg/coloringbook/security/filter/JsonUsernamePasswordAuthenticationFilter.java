package com.hansjoerg.coloringbook.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.hansjoerg.coloringbook.payload.LoginRequest; // Correct import
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.http.MediaType;

import java.io.IOException;

/**
 * Custom filter to handle JSON-based login requests with "email" and "password".
 */
public class JsonUsernamePasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private static final Logger logger = LoggerFactory.getLogger(JsonUsernamePasswordAuthenticationFilter.class);
    private final ObjectMapper objectMapper = new ObjectMapper();

    public JsonUsernamePasswordAuthenticationFilter() {
        super();
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        logger.debug("Attempting JSON authentication for request URI: {}", request.getRequestURI());
        if (!request.getMethod().equals("POST")) {
            logger.warn("Authentication method not supported: {} for URI: {}", request.getMethod(), request.getRequestURI());
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        }

        String contentType = request.getContentType();
        logger.debug("Request Content-Type: {}", contentType);

        if (contentType == null || !contentType.contains(MediaType.APPLICATION_JSON_VALUE)) {
            logger.warn("Authentication request did not have Content-Type: application/json for URI: {}", request.getRequestURI());
            throw new AuthenticationServiceException("Authentication request must be application/json");
        }

        try {
            // Use the LoginRequest DTO from the payload package
            LoginRequest loginRequest = objectMapper.readValue(request.getInputStream(), LoginRequest.class);
            logger.debug("Parsed login request for email: {}", loginRequest.getEmail());
            UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(
                    loginRequest.getEmail(), loginRequest.getPassword());
            setDetails(request, authRequest);
            return this.getAuthenticationManager().authenticate(authRequest);
        } catch (IOException e) {
            logger.error("Failed to parse authentication request body for URI: {}", request.getRequestURI(), e);
            throw new AuthenticationServiceException("Failed to parse authentication request body", e);
        }
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        logger.error("Unsuccessful authentication in JsonUsernamePasswordAuthenticationFilter: {}", failed.getMessage());
        getFailureHandler().onAuthenticationFailure(request, response, failed);
    }
}
