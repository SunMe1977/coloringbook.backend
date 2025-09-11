package com.hansjoerg.coloringbook.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.hansjoerg.coloringbook.payload.ApiResponse;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class JsonAuthenticationFailureHandler implements AuthenticationFailureHandler {

    private static final Logger logger = LoggerFactory.getLogger(JsonAuthenticationFailureHandler.class);
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        logger.error("Login failed via JsonAuthenticationFailureHandler: {}", exception.getMessage());
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        String errorJson = objectMapper.writeValueAsString(new ApiResponse(false, "Login failed: " + exception.getMessage()));
        logger.debug("Attempting to write error JSON to response from JsonAuthenticationFailureHandler: {}", errorJson);
        response.getWriter().write(errorJson);
        response.getWriter().flush();
        logger.debug("Successfully wrote error JSON to response from JsonAuthenticationFailureHandler.");
    }
}
