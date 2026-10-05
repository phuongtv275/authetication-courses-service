package com.example.productservice.security.jwt;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.DecodingException;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.security.Key;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class JwtTokenValidatorTest {

    private static final String SECRET_KEY = "404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970";
    private JwtTokenValidator validator;

    @BeforeEach
    void setUp() {
        validator = new JwtTokenValidator();
        ReflectionTestUtils.setField(validator, "secretKey", SECRET_KEY);
        validator.init();
    }

    private String generateTestToken(String username, List<String> roles, long expirationMs) {
        Key key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(SECRET_KEY));
        return Jwts.builder()
                .setSubject(username)
                .addClaims(Map.of("username", username, "roles", roles))
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expirationMs))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    @Test
    @DisplayName("validateToken should return true for valid token")
    void shouldValidateValidToken() {
        String token = generateTestToken("john", List.of("ROLE_USER"), 60000);
        assertTrue(validator.validateToken(token));
        assertEquals("john", validator.getUsername(token));
        assertEquals(List.of("ROLE_USER"), validator.getRoles(token));
    }

    @Test
    @DisplayName("validateToken should return false for expired token")
    void shouldReturnFalseForExpiredToken() {
        String token = generateTestToken("john", List.of("ROLE_USER"), -1000);
        assertFalse(validator.validateToken(token));
    }

    @Test
    @DisplayName("validateToken should return false for invalid signature")
    void shouldReturnFalseForInvalidSignature() {
        String wrongKey = "1111111111111111111111111111111111111111111111111111111111111111";
        Key key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(wrongKey));
        String token = Jwts.builder()
                .setSubject("john")
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        assertFalse(validator.validateToken(token));
    }

    @Test
    @DisplayName("init should fail fast on startup if secret is not valid Base64")
    void shouldFailFastWhenSecretIsNotBase64() {
        JwtTokenValidator badValidator = new JwtTokenValidator();
        ReflectionTestUtils.setField(badValidator, "secretKey", "invalid_base64_string!@#$");

        assertThrows(DecodingException.class, badValidator::init);
    }
}
