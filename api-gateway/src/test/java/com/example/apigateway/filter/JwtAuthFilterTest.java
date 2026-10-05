package com.example.apigateway.filter;

import com.example.apigateway.config.JwtProperties;
import com.example.apigateway.security.JwtUtils;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JwtAuthFilterTest {

    private static final String VALID_BASE64_SECRET = "404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970";

    @Mock
    private ReactiveStringRedisTemplate redisTemplate;

    @Mock
    private WebFilterChain filterChain;

    private JwtAuthFilter jwtAuthFilter;
    private JwtUtils jwtUtils;
    private ObjectMapper objectMapper;
    private SecretKey signingKey;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();

        JwtProperties jwtProperties = new JwtProperties();
        jwtProperties.setSecretKey(VALID_BASE64_SECRET);
        jwtProperties.setWhitelistPaths(List.of(
                "/identity/api/v1/auth/**",
                "/identity/api/auth/**",
                "/api/v1/auth/**",
                "/api/auth/**"
        ));

        jwtUtils = new JwtUtils(jwtProperties);
        jwtAuthFilter = new JwtAuthFilter(jwtUtils, jwtProperties, objectMapper, redisTemplate);

        byte[] keyBytes = Decoders.BASE64.decode(VALID_BASE64_SECRET);
        signingKey = Keys.hmacShaKeyFor(keyBytes);
    }

    private String createToken(String username, String jti, List<String> roles, long expirationOffsetMs) {
        return createToken(username, jti, null, roles, null, expirationOffsetMs);
    }

    private String createToken(String username, String jti, String role, List<String> roles, List<String> permissions, long expirationOffsetMs) {
        var builder = Jwts.builder()
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + expirationOffsetMs))
                .signWith(signingKey);

        if (jti != null) {
            builder.id(jti);
        }
        if (role != null) {
            builder.claim("role", role);
        }
        if (roles != null) {
            builder.claim("roles", roles);
        }
        if (permissions != null) {
            builder.claim("permissions", permissions);
        }
        return builder.compact();
    }

    @Test
    @DisplayName("Whitelisted path should bypass JWT validation and proceed in chain")
    void shouldBypassWhitelistedPath() {
        MockServerHttpRequest request = MockServerHttpRequest.post("/identity/api/v1/auth/login").build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        when(filterChain.filter(any())).thenReturn(Mono.empty());

        StepVerifier.create(jwtAuthFilter.filter(exchange, filterChain))
                .verifyComplete();

        verify(filterChain).filter(any());
        verifyNoInteractions(redisTemplate);
    }

    @Test
    @DisplayName("Request with missing Authorization header should return 401 Unauthorized")
    void shouldReturn401WhenAuthHeaderMissing() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/product/api/products").build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        StepVerifier.create(jwtAuthFilter.filter(exchange, filterChain))
                .verifyComplete();

        assertEquals(HttpStatus.UNAUTHORIZED, exchange.getResponse().getStatusCode());
        verifyNoInteractions(filterChain);
        verifyNoInteractions(redisTemplate);
    }

    @Test
    @DisplayName("Request with expired token should return 401 Unauthorized")
    void shouldReturn401WhenTokenIsExpired() {
        String expiredToken = createToken("john_doe", UUID.randomUUID().toString(), List.of("ROLE_USER"), -10000);
        MockServerHttpRequest request = MockServerHttpRequest.get("/product/api/products")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + expiredToken)
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        StepVerifier.create(jwtAuthFilter.filter(exchange, filterChain))
                .verifyComplete();

        assertEquals(HttpStatus.UNAUTHORIZED, exchange.getResponse().getStatusCode());
        verifyNoInteractions(filterChain);
        verifyNoInteractions(redisTemplate);
    }

    @Test
    @DisplayName("Request with token missing jti claim should return 401 Unauthorized")
    void shouldReturn401WhenTokenMissingJti() {
        String tokenWithoutJti = createToken("john_doe", null, List.of("ROLE_USER"), 60000);
        MockServerHttpRequest request = MockServerHttpRequest.get("/product/api/products")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenWithoutJti)
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        StepVerifier.create(jwtAuthFilter.filter(exchange, filterChain))
                .verifyComplete();

        assertEquals(HttpStatus.UNAUTHORIZED, exchange.getResponse().getStatusCode());
        verifyNoInteractions(filterChain);
        verifyNoInteractions(redisTemplate);
    }

    @Test
    @DisplayName("Request with blacklisted token should return 401 Unauthorized and not call chain.filter")
    void shouldReturn401WhenTokenIsBlacklistedInRedis() {
        String jti = UUID.randomUUID().toString();
        String blacklistedToken = createToken("john_doe", jti, List.of("ROLE_USER"), 60000);

        MockServerHttpRequest request = MockServerHttpRequest.get("/product/api/products")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + blacklistedToken)
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        when(redisTemplate.hasKey("blacklist:" + jti)).thenReturn(Mono.just(true));

        StepVerifier.create(jwtAuthFilter.filter(exchange, filterChain))
                .verifyComplete();

        assertEquals(HttpStatus.UNAUTHORIZED, exchange.getResponse().getStatusCode());
        verify(redisTemplate).hasKey("blacklist:" + jti);
        verifyNoInteractions(filterChain);
    }

    @Test
    @DisplayName("Request with valid non-blacklisted token should mutate headers and call chain.filter")
    void shouldPassWhenTokenIsValidAndNotBlacklisted() {
        String jti = UUID.randomUUID().toString();
        String validToken = createToken("admin_user", jti, List.of("ROLE_ADMIN", "ROLE_USER"), 60000);

        MockServerHttpRequest request = MockServerHttpRequest.get("/product/api/products")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + validToken)
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        when(redisTemplate.hasKey("blacklist:" + jti)).thenReturn(Mono.just(false));
        when(filterChain.filter(any())).thenAnswer(invocation -> {
            org.springframework.web.server.ServerWebExchange mutatedExchange = invocation.getArgument(0);
            HttpHeaders headers = mutatedExchange.getRequest().getHeaders();

            assertNotNull(headers.getFirst("X-Correlation-Id"));
            assertEquals("admin_user", headers.getFirst("X-User-Id"));
            assertEquals("ROLE_ADMIN", headers.getFirst("X-User-Role"));
            assertEquals("ROLE_ADMIN,ROLE_USER", headers.getFirst("X-User-Roles"));
            assertEquals("[]", headers.getFirst("X-User-Permissions"));
            return Mono.empty();
        });

        StepVerifier.create(jwtAuthFilter.filter(exchange, filterChain))
                .verifyComplete();

        assertNull(exchange.getResponse().getStatusCode(), "Status code should remain null on successful pass");
        verify(redisTemplate).hasKey("blacklist:" + jti);
        verify(filterChain).filter(any());
    }

    @Test
    @DisplayName("Request with STUDENT role and COURSE_READ permission to /api/courses should inject headers correctly")
    void shouldPassAndInjectStudentRoleAndPermissionsForCourses() {
        String jti = UUID.randomUUID().toString();
        String validToken = createToken("student_alice", jti, "STUDENT", List.of("STUDENT"), List.of("COURSE_READ"), 60000);

        MockServerHttpRequest request = MockServerHttpRequest.get("/api/courses")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + validToken)
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        when(redisTemplate.hasKey("blacklist:" + jti)).thenReturn(Mono.just(false));
        when(filterChain.filter(any())).thenAnswer(invocation -> {
            org.springframework.web.server.ServerWebExchange mutatedExchange = invocation.getArgument(0);
            HttpHeaders headers = mutatedExchange.getRequest().getHeaders();

            assertNotNull(headers.getFirst("X-Correlation-Id"));
            assertEquals("student_alice", headers.getFirst("X-User-Id"));
            assertEquals("STUDENT", headers.getFirst("X-User-Role"));
            assertEquals("STUDENT", headers.getFirst("X-User-Roles"));
            assertEquals("[\"COURSE_READ\"]", headers.getFirst("X-User-Permissions"));
            return Mono.empty();
        });

        StepVerifier.create(jwtAuthFilter.filter(exchange, filterChain))
                .verifyComplete();

        assertNull(exchange.getResponse().getStatusCode());
        verify(redisTemplate).hasKey("blacklist:" + jti);
        verify(filterChain).filter(any());
    }

    @Test
    @DisplayName("Request with existing X-Correlation-Id header should preserve it")
    void shouldPreserveExistingCorrelationId() {
        String jti = UUID.randomUUID().toString();
        String validToken = createToken("admin_user", jti, List.of("ROLE_USER"), 60000);

        MockServerHttpRequest request = MockServerHttpRequest.get("/product/api/products")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + validToken)
                .header("X-Correlation-Id", "custom-client-corr-id-999")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        when(redisTemplate.hasKey("blacklist:" + jti)).thenReturn(Mono.just(false));
        when(filterChain.filter(any())).thenAnswer(invocation -> {
            org.springframework.web.server.ServerWebExchange mutatedExchange = invocation.getArgument(0);
            assertEquals("custom-client-corr-id-999", mutatedExchange.getRequest().getHeaders().getFirst("X-Correlation-Id"));
            return Mono.empty();
        });

        StepVerifier.create(jwtAuthFilter.filter(exchange, filterChain))
                .verifyComplete();

        assertNull(exchange.getResponse().getStatusCode());
    }

    @Test
    @DisplayName("Request with token missing subject (username) should return 401 Unauthorized")
    void shouldReturn401WhenTokenMissingSubject() {
        var builder = Jwts.builder()
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 60000))
                .id(UUID.randomUUID().toString())
                .signWith(signingKey);
        String tokenWithoutSub = builder.compact();

        MockServerHttpRequest request = MockServerHttpRequest.get("/product/api/products")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenWithoutSub)
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        StepVerifier.create(jwtAuthFilter.filter(exchange, filterChain))
                .verifyComplete();

        assertEquals(HttpStatus.UNAUTHORIZED, exchange.getResponse().getStatusCode());
        verifyNoInteractions(filterChain);
        verifyNoInteractions(redisTemplate);
    }

    @Test
    @DisplayName("Downstream error should NOT be swallowed by filter onErrorResume")
    void shouldNotSwallowDownstreamError() {
        String jti = UUID.randomUUID().toString();
        String validToken = createToken("john_doe", jti, List.of("ROLE_USER"), 60000);

        MockServerHttpRequest request = MockServerHttpRequest.get("/product/api/products")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + validToken)
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        when(redisTemplate.hasKey("blacklist:" + jti)).thenReturn(Mono.just(false));
        when(filterChain.filter(any())).thenReturn(Mono.error(new IllegalStateException("Downstream service crashed")));

        StepVerifier.create(jwtAuthFilter.filter(exchange, filterChain))
                .expectErrorMatches(throwable -> throwable instanceof IllegalStateException
                        && throwable.getMessage().equals("Downstream service crashed"))
                .verify();

        verify(filterChain).filter(any());
    }

    @Test
    @DisplayName("When Redis fails with exception, filter should return 500 without crashing")
    void shouldReturn500WhenRedisFails() {
        String jti = UUID.randomUUID().toString();
        String validToken = createToken("john_doe", jti, List.of("ROLE_USER"), 60000);

        MockServerHttpRequest request = MockServerHttpRequest.get("/product/api/products")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + validToken)
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        when(redisTemplate.hasKey("blacklist:" + jti))
                .thenReturn(Mono.error(new org.springframework.data.redis.RedisConnectionFailureException("Redis offline")));

        StepVerifier.create(jwtAuthFilter.filter(exchange, filterChain))
                .verifyComplete();

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, exchange.getResponse().getStatusCode());
        verifyNoInteractions(filterChain);
    }
}
