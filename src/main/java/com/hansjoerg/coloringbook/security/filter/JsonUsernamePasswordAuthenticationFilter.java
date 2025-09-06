package com.hansjoerg.coloringbook.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;

/**
 * Custom filter to handle JSON-based login requests with "email" and "password".
 */
public class JsonUsernamePasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
        String email = request.getParameter("email");
        String password = request.getParameter("password");

        if (email == null || password == null) {
            throw new RuntimeException("Missing email or password");
        }

        UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(email, password);
        setDetails(request, authRequest);

        return this.getAuthenticationManager().authenticate(authRequest);
    }


    // Optional: override if you want to customize post-auth behavior
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            FilterChain chain, Authentication authResult)
            throws IOException, ServletException {
        super.successfulAuthentication(request, response, chain, authResult);
    }

    // DTO for login payload
    @Setter
    @Getter
    public static class LoginRequest {
        private String email;
        private String password;
    }
}
