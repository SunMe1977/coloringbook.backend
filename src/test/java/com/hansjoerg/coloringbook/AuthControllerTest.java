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
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
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

    @BeforeEach
    void setUp() {
        userRepository.deleteAll();
    }

    @Test
    void testUserRegistration() throws Exception {
        String email = "test@example.com";
        String name = "Test User";
        SignUpRequest signUpRequest = new SignUpRequest(name, email, "password123");

        mockMvc.perform(post("/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(signUpRequest)))
                .andExpect(status().isOk()) // Changed from isCreated() to isOk()
                .andExpect(jsonPath("$.accessToken").exists()) // Expect accessToken
                .andExpect(jsonPath("$.tokenType").value("Bearer")); // Expect tokenType

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
                .andExpect(status().isOk()); // Expect 200 OK for the first signup

        SignUpRequest signUpRequest2 = new SignUpRequest("Test User 2", "duplicate@example.com", "password456");
        mockMvc.perform(post("/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(signUpRequest2)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("Email address already in use."));
    }

    @Test
    void testUserLogin_Success() throws Exception {
        // First, register a user (this will now return 200 OK with a token)
        SignUpRequest signUpRequest = new SignUpRequest("Login User", "login@example.com", "loginpassword");
        mockMvc.perform(post("/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(signUpRequest)))
                .andExpect(status().isOk()); // Expect 200 OK for signup

        // Now, attempt to log in
        LoginRequest loginRequest = new LoginRequest("login@example.com", "loginpassword");
        MvcResult result = mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk()) // Expect 200 OK for successful local login
                .andExpect(jsonPath("$.accessToken").exists()) // Expect accessToken in JSON body
                .andExpect(jsonPath("$.tokenType").value("Bearer")) // Expect tokenType in JSON body
                .andReturn();

        String responseContent = result.getResponse().getContentAsString();
        AuthResponse authResponse = objectMapper.readValue(responseContent, AuthResponse.class);
        String token = authResponse.getAccessToken();

        assertNotNull(token);
        assertTrue(tokenProvider.validateToken(token));
    }

    @Test
    void testUserLogin_Failure_WrongPassword() throws Exception {
        // First, register a user (this will now return 200 OK with a token)
        SignUpRequest signUpRequest = new SignUpRequest("Wrong Pass User", "wrongpass@example.com", "correctpassword");
        mockMvc.perform(post("/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(signUpRequest)))
                .andExpect(status().isOk()); // Expect 200 OK for signup

        LoginRequest loginRequest = new LoginRequest("wrongpass@example.com", "incorrectpassword");
        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.message").value("Login failed: Bad credentials"));
    }

    @Test
    void testUserLogin_Failure_NonExistentUser() throws Exception {
        LoginRequest loginRequest = new LoginRequest("nonexistent@example.com", "anypassword");
        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.message").value("Login failed: Bad credentials"));
    }
}
