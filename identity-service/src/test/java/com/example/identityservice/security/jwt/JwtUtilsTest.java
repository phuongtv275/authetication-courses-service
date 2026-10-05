package com.example.identityservice.security.jwt;

import com.example.identityservice.models.constants.RoleName;
import com.example.identityservice.models.entities.Role;
import com.example.identityservice.models.entities.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.security.Key;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class JwtUtilsTest {

    private static final String VALID_BASE64_SECRET = "404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970";
    private JwtUtils jwtUtils;

    @BeforeEach
    void setUp() {
        jwtUtils = new JwtUtils(new com.example.identityservice.security.permission.PermissionResolver());
        ReflectionTestUtils.setField(jwtUtils, "secretKey", VALID_BASE64_SECRET);
        ReflectionTestUtils.setField(jwtUtils, "accessTokenExpiration", 900000L);
        jwtUtils.init();
    }

    @Test
    @DisplayName("generateAccessToken should create a valid JWT verified with Base64 decoded key like Gateway")
    void shouldGenerateAccessTokenSuccessfully() {
        Role role = Role.builder().id(1L).roleName(RoleName.ROLE_USER).build();
        User user = User.builder()
                .id(1L)
                .username("john_doe")
                .fullName("John Doe")
                .roles(Set.of(role))
                .build();

        String token = jwtUtils.generateAccessToken(user);

        assertNotNull(token);
        assertFalse(token.isBlank());

        // Verify using independent Base64 key decoding (matching Gateway's logic)
        Key gatewayVerificationKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(VALID_BASE64_SECRET));
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(gatewayVerificationKey)
                .build()
                .parseClaimsJws(token)
                .getBody();

        assertEquals("john_doe", claims.getSubject());
        assertEquals("john_doe", claims.get("username"));
        assertEquals("ROLE_USER", claims.get("role"));
        @SuppressWarnings("unchecked")
        List<String> roles = (List<String>) claims.get("roles");
        assertNotNull(roles);
        assertTrue(roles.contains("ROLE_USER"));
        @SuppressWarnings("unchecked")
        List<String> permissions = (List<String>) claims.get("permissions");
        assertNotNull(permissions);
        assertTrue(permissions.contains("COURSE_READ"));
        assertNotNull(claims.getExpiration());
        assertTrue(claims.getExpiration().getTime() > System.currentTimeMillis());

        // Verify jti claim
        assertNotNull(claims.getId());
        assertFalse(claims.getId().isBlank());
        assertEquals(claims.getId(), jwtUtils.extractJti(token));
        assertEquals("john_doe", jwtUtils.extractUsername(token));
        assertEquals("ROLE_USER", jwtUtils.extractRole(token));
        assertEquals(List.of("COURSE_READ"), jwtUtils.extractPermissions(token));
        assertNotNull(jwtUtils.extractExpiration(token));
        assertTrue(jwtUtils.validateToken(token));
    }

    @Test
    @DisplayName("generateAccessToken for STUDENT and INSTRUCTOR should have correct role and permissions")
    void shouldGenerateCorrectRoleAndPermissionsForStudentAndInstructor() {
        Role studentRole = Role.builder().id(1L).roleName(RoleName.STUDENT).build();
        User student = User.builder().username("alice").roles(Set.of(studentRole)).build();
        String studentToken = jwtUtils.generateAccessToken(student);
        assertEquals("STUDENT", jwtUtils.extractRole(studentToken));
        assertEquals(List.of("COURSE_READ"), jwtUtils.extractPermissions(studentToken));

        Role instructorRole = Role.builder().id(2L).roleName(RoleName.INSTRUCTOR).build();
        User instructor = User.builder().username("bob").roles(Set.of(instructorRole)).build();
        String instructorToken = jwtUtils.generateAccessToken(instructor);
        assertEquals("INSTRUCTOR", jwtUtils.extractRole(instructorToken));
        List<String> instructorPerms = jwtUtils.extractPermissions(instructorToken);
        assertTrue(instructorPerms.contains("COURSE_READ"));
        assertTrue(instructorPerms.contains("COURSE_WRITE"));
    }

    @Test
    @DisplayName("validateToken should return false for invalid token string")
    void shouldReturnFalseForInvalidToken() {
        assertFalse(jwtUtils.validateToken("invalid.token.string"));
    }

    @Test
    @DisplayName("init should fail fast on startup if secret is not valid Base64")
    void shouldFailFastWhenSecretIsNotBase64() {
        JwtUtils badJwtUtils = new JwtUtils(new com.example.identityservice.security.permission.PermissionResolver());
        ReflectionTestUtils.setField(badJwtUtils, "secretKey", "invalid_base64_secret_!@#$%");

        assertThrows(io.jsonwebtoken.io.DecodingException.class, badJwtUtils::init);
    }

    @Test
    @DisplayName("extractAllClaims should return claims even when token is expired without throwing ExpiredJwtException")
    void shouldExtractClaimsWhenTokenIsExpired() {
        Key key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(VALID_BASE64_SECRET));
        String expiredToken = Jwts.builder()
                .setSubject("expired_user")
                .setId("expired-jti-123")
                .setIssuedAt(new java.util.Date(System.currentTimeMillis() - 100000))
                .setExpiration(new java.util.Date(System.currentTimeMillis() - 50000))
                .signWith(key, io.jsonwebtoken.SignatureAlgorithm.HS256)
                .compact();

        assertFalse(jwtUtils.validateToken(expiredToken));

        Claims claims = jwtUtils.extractAllClaims(expiredToken);
        assertNotNull(claims);
        assertEquals("expired_user", claims.getSubject());
        assertEquals("expired-jti-123", claims.getId());
        assertEquals("expired_user", jwtUtils.extractUsername(expiredToken));
        assertEquals("expired-jti-123", jwtUtils.extractJti(expiredToken));
        assertNotNull(jwtUtils.extractExpiration(expiredToken));
    }
}
