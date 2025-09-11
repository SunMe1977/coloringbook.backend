package com.hansjoerg.coloringbook.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.hansjoerg.coloringbook.payload.ApiResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

public class RestAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private static final Logger logger = LoggerFactory.getLogger(RestAuthenticationEntryPoint.class);
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void commence(HttpServletRequest httpServletRequest,
                         HttpServletResponse httpServletResponse,
                         AuthenticationException e) throws IOException, ServletException {
        logger.error("Responding with unauthorized error. Message - {}", e.getMessage());

        httpServletResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        httpServletResponse.setContentType(MediaType.APPLICATION_JSON_VALUE);
        String errorJson = objectMapper.writeValueAsString(new ApiResponse(false, "Unauthorized: " + e.getLocalizedMessage()));
        logger.debug("Sending error JSON from RestAuthenticationEntryPoint: {}", errorJson);
        httpServletResponse.getWriter().write(errorJson);
        httpServletResponse.getWriter().flush();
        logger.debug("Successfully wrote error JSON to response from RestAuthenticationEntryPoint.");
    }
}
