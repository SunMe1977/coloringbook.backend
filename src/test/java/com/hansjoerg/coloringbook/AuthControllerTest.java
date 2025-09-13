package com.hansjoerg.coloringbook;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.hansjoerg.coloringbook.config.AppProperties;
import com.hansjoerg.coloringbook.model.AuthProvider;
import com.hansjoerg.coloringbook.model.User;
import com.hansjoerg.coloringbook.payload.AuthResponse;
import com.hansjoerg.coloringbook.payload.LoginRequest;
import com.hansjoerg.coloringbook.payload.SignUpRequest;
import com.hansjoerg.coloringbook.repository.UserRepository;
import com.hansjoerg.coloringbook.security.TokenProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.Locale;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {
        "app.rate-limit.login-rps=1000.0", // Effectively disable rate limiting for tests
        "app.rate-limit.signup-rps=1000.0"
})
public class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private TokenProvider tokenProvider;

    @Autowired
    private AppProperties appProperties;

    @Autowired
    private MessageSource messageSource;

    @BeforeEach
    void setUp() {
        userRepository.deleteAll();
        // Ensure a consistent locale for tests if messages are being checked
        LocaleContextHolder.setLocale(Locale.ENGLISH); // Explicitly set to English
    }

    @Test
    void testUserRegistration() throws Exception {
        String email = "test@example.com";
        String name = "Test User";
        SignUpRequest signUpRequest = new SignUpRequest(name, email, "password123");

        MvcResult result = mockMvc.perform(post("/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(signUpRequest)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.accessToken").exists()) // Check for accessToken
                .andExpect(jsonPath("$.tokenType").value("Bearer")) // Check for tokenType
                .andReturn();

        String responseContent = result.getResponse().getContentAsString();
        AuthResponse authResponse = objectMapper.readValue(responseContent, AuthResponse.class);
        String token = authResponse.getAccessToken();

        assertNotNull(token, "Access token should not be null");
        assertTrue(tokenProvider.validateToken(token), "Generated token should be valid");

        Optional<User> registeredUser = userRepository.findByEmail(email);
        assertTrue(registeredUser.isPresent(), "User should be found in the database after registration");
        assertEquals(name, registeredUser.get().getName());
        assertEquals(email, registeredUser.get().getEmail());
        assertEquals(AuthProvider.local, registeredUser.get().getProvider());
        assertNotNull(registeredUser.get().getPassword());
    }

    @Test
    void testUserRegistration_DuplicateEmail() throws Exception {
        SignUpRequest signUpRequest1 = new SignUpRequest("Test User 1", "duplicate@example.com", "password123");
        mockMvc.perform(post("/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(signUpRequest1)))
                .andExpect(status().isCreated());

        SignUpRequest signUpRequest2 = new SignUpRequest("Test User 2", "duplicate@example.com", "password456");
        String expectedErrorMessage = messageSource.getMessage("error.emailAlreadyInUse", null, Locale.ENGLISH); // Use Locale.ENGLISH

        mockMvc.perform(post("/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(signUpRequest2)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.message").value(expectedErrorMessage));
    }

    @Test
    void testUserLogin_Success() throws Exception {
        // First, register a user
        SignUpRequest signUpRequest = new SignUpRequest("Login User", "login@example.com", "loginpassword");
        mockMvc.perform(post("/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(signUpRequest)))
                .andExpect(status().isCreated());

        // Now, attempt to log in
        LoginRequest loginRequest = new LoginRequest("login@example.com", "loginpassword");
        MvcResult result = mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andReturn();

        String responseContent = result.getResponse().getContentAsString();
        AuthResponse authResponse = objectMapper.readValue(responseContent, AuthResponse.class);
        String token = authResponse.getAccessToken();

        assertNotNull(token);
        assertTrue(tokenProvider.validateToken(token));
    }

    @Test
    void testUserLogin_Failure_WrongPassword() throws Exception {
        SignUpRequest signUpRequest = new SignUpRequest("Wrong Pass User", "wrongpass@example.com", "correctpassword");
        mockMvc.perform(post("/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(signUpRequest)))
                .andExpect(status().isCreated());

        LoginRequest loginRequest = new LoginRequest("wrongpass@example.com", "incorrectpassword");
        String expectedErrorMessage = messageSource.getMessage("error.loginFailed", new Object[]{"Bad credentials"}, Locale.ENGLISH); // Use Locale.ENGLISH

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.message").value(expectedErrorMessage));
    }

    @Test
    void testUserLogin_Failure_NonExistentUser() throws Exception {
        LoginRequest loginRequest = new LoginRequest("nonexistent@example.com", "anypassword");
        String expectedErrorMessage = messageSource.getMessage("error.loginFailed", new Object[]{"Bad credentials"}, Locale.ENGLISH); // Use Locale.ENGLISH

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.message").value(expectedErrorMessage));
    }
}
