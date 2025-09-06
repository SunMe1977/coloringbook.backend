package com.hansjoerg.coloringbook;

import com.hansjoerg.coloringbook.config.AppProperties;
import com.hansjoerg.coloringbook.security.TokenProvider;
import com.hansjoerg.coloringbook.security.UserPrincipal;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;

//import static org.junit.jupiter.api.Assertions.*;

@Disabled
@SpringBootTest
public class TokenProviderTest {

    @Autowired
    private TokenProvider tokenProvider;

    @Autowired
    private AppProperties appProperties;

    @Test
    public void testCreateAndValidateToken() {
        Authentication auth = new UsernamePasswordAuthenticationToken(
                new UserPrincipal(1L, "user@example.com", "Test User", null),
                null,
                Collections.emptyList()
        );

        String token = tokenProvider.createToken(auth);
        assertTrue(tokenProvider.validateToken(token));
        assertEquals(1L, tokenProvider.getUserIdFromToken(token));
    }

    @Test
    public void testExpiredTokenShouldFailValidation() throws InterruptedException {
        long originalExpiration = appProperties.getAuth().getTokenExpirationMsec();
        appProperties.getAuth().setTokenExpirationMsec(1); // 1 ms

        Authentication auth = new UsernamePasswordAuthenticationToken(
                new UserPrincipal(2L, "expired@example.com", "Expired User", null),
                null,
                Collections.emptyList()
        );

        String token = tokenProvider.createToken(auth);
        Thread.sleep(10); // wait for expiration

        assertFalse(tokenProvider.validateToken(token));
        appProperties.getAuth().setTokenExpirationMsec(originalExpiration); // restore
    }

    @Test
    public void testMalformedTokenShouldFailValidation() {
        String malformedToken = "this.is.not.a.valid.jwt";
        assertFalse(tokenProvider.validateToken(malformedToken));
    }

    @Test
    public void testTamperedTokenShouldFailValidation() {
        Authentication auth = new UsernamePasswordAuthenticationToken(
                new UserPrincipal(3L, "tampered@example.com", "Tampered User", null),
                null,
                Collections.emptyList()
        );

        String token = tokenProvider.createToken(auth);

        // Split token into parts
        String[] parts = token.split("\\.");
        assertEquals(3, parts.length, "JWT should have 3 parts");

        // Replace signature with garbage
        String tamperedToken = parts[0] + "." + parts[1] + "." + "invalidsignature";

        boolean isValid;
        try {
            isValid = tokenProvider.validateToken(tamperedToken);
        } catch (Exception e) {
            isValid = false; // expected failure
        }

        assertFalse(isValid, "Tampered token should not be valid");
    }

    @Test
    public void testExtractUserIdFromToken() {
        Authentication auth = new UsernamePasswordAuthenticationToken(
                new UserPrincipal(42L, "user@example.com", "User", null),
                null,
                Collections.emptyList()
        );

        String token = tokenProvider.createToken(auth);
        Long userId = tokenProvider.getUserIdFromToken(token);

        assertEquals(42L, userId);
    }
}
