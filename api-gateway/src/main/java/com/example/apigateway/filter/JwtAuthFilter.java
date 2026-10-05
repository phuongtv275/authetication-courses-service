package com.example.apigateway.filter;

import com.example.apigateway.config.JwtProperties;
import com.example.apigateway.dto.ErrorResponse;
import com.example.apigateway.security.JwtUtils;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.List;
import java.util.UUID;

/**
 * GlobalFilter chặn TẤT CẢ request đi qua Gateway và validate JWT.
 *
 * Luồng xử lý:
 * 1. Tạo correlationId để trace request xuyên suốt log.
 * 2. Kiểm tra path có thuộc whitelist không (auth endpoints) → bỏ qua nếu có.
 * 3. Lấy header Authorization, kiểm tra định dạng "Bearer <token>".
 * 4. Parse và verify JWT bằng JJWT (chữ ký + hạn dùng).
 * 5. Kiểm tra Redis Blacklist (Reactive non-blocking): nếu jti nằm trong Redis -> 401 Unauthorized.
 * 6. Nếu hợp lệ và không nằm trong blacklist, forward request kèm context headers (correlationId, X-User-Id, ...).
 *
 * Implements {@link WebFilter} thay vì {@link org.springframework.cloud.gateway.filter.GlobalFilter}
 * vì Spring Cloud Gateway 4.x khuyến khích dùng WebFilter cho logic cross-cutting toàn cục.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthFilter implements WebFilter, Ordered {

    public static final String BLACKLIST_KEY_PREFIX = "blacklist:";
    private static final String BEARER_PREFIX = "Bearer ";
    private static final String CORRELATION_ID_HEADER = "X-Correlation-Id";

    private final JwtUtils jwtUtils;
    private final JwtProperties jwtProperties;
    private final ObjectMapper objectMapper;
    private final ReactiveStringRedisTemplate redisTemplate;
    private final AntPathMatcher antPathMatcher = new AntPathMatcher();

    /**
     * Đặt ORDER thấp nhất (chạy đầu tiên) để filter này luôn chạy
     * trước các filter khác của Spring Cloud Gateway.
     */
    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getPath().value();

        // Bảo lưu correlationId nếu client/proxy gửi lên, hoặc tạo mới nếu chưa có
        String incomingCorrId = request.getHeaders().getFirst(CORRELATION_ID_HEADER);
        String correlationId = (incomingCorrId != null && !incomingCorrId.isBlank())
                ? incomingCorrId.trim()
                : UUID.randomUUID().toString();
        log.debug("[{}] Incoming request: {} {}", correlationId, request.getMethod(), path);

        // Bước 1: Kiểm tra whitelist — nếu là auth endpoint thì bỏ qua validate JWT
        if (isWhitelisted(path)) {
            log.debug("[{}] Path '{}' is whitelisted, skipping JWT validation", correlationId, path);
            // Forward kèm correlationId để downstream service có thể trace
            ServerHttpRequest mutatedRequest = request.mutate()
                    .header(CORRELATION_ID_HEADER, correlationId)
                    .build();
            return chain.filter(exchange.mutate().request(mutatedRequest).build());
        }

        // Bước 2: Lấy và kiểm tra Authorization header
        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            log.warn("[{}] Missing or malformed Authorization header for path: {}", correlationId, path);
            return writeErrorResponse(
                    exchange,
                    HttpStatus.UNAUTHORIZED,
                    "Authorization header missing or malformed. Expected format: Bearer <token>",
                    path
            );
        }

        // Bước 3: Tách token ra khỏi tiền tố "Bearer "
        String token = authHeader.substring(BEARER_PREFIX.length());

        try {
            // Bước 4: Parse và verify JWT — JJWT sẽ tự kiểm tra chữ ký + thời hạn
            var claims = jwtUtils.parseToken(token);
            String username = claims.getSubject();
            String jti = claims.getId();

            // Kiểm tra claim sub (username)
            if (username == null || username.isBlank()) {
                log.warn("[{}] Token missing 'sub' (username) claim for path: {}", correlationId, path);
                return writeErrorResponse(exchange, HttpStatus.UNAUTHORIZED, "Invalid token: missing subject", path);
            }

            // Trích xuất claim 'role' (dạng chuỗi đơn theo Bài 1, 2)
            String roleClaim = claims.get("role", String.class);

            // Trích xuất roles từ JWT claims (được serialize thành List<String>)
            @SuppressWarnings("unchecked")
            List<String> roles = claims.get("roles", List.class);

            String resolvedRole = "";
            if (roleClaim != null && !roleClaim.isBlank()) {
                resolvedRole = roleClaim;
            } else if (roles != null && !roles.isEmpty()) {
                resolvedRole = roles.stream()
                        .filter(r -> r.equals("INSTRUCTOR") || r.equals("ROLE_ADMIN"))
                        .findFirst()
                        .orElse(roles.get(0));
            }
            final String primaryRole = resolvedRole;

            // Trích xuất claim 'permissions' (PBAC - Bài 6) và serialize thành JSON chuỗi
            @SuppressWarnings("unchecked")
            List<String> permissions = claims.get("permissions", List.class);
            String serializedPermissions = "[]";
            if (permissions != null && !permissions.isEmpty()) {
                try {
                    serializedPermissions = objectMapper.writeValueAsString(permissions);
                } catch (JsonProcessingException e) {
                    log.warn("[{}] Failed to serialize permissions to JSON: {}", correlationId, e.getMessage());
                }
            }
            final String permissionsJson = serializedPermissions;

            log.debug("[{}] JWT valid — user: '{}', jti: '{}', role: '{}', permissions: {}, path: {}",
                    correlationId, username, jti, primaryRole, permissionsJson, path);

            // Kiểm tra claim jti
            if (jti == null || jti.isBlank()) {
                log.warn("[{}] Token missing 'jti' claim for path: {}", correlationId, path);
                return writeErrorResponse(exchange, HttpStatus.UNAUTHORIZED, "Invalid token: missing jti claim", path);
            }

            // Bước 5: Kiểm tra Redis Blacklist (Reactive, Non-blocking)
            // Note giải thích logic:
            // 1. Truy vấn Redis key "blacklist:{jti}" với timeout 2 giây.
            // 2. Tách biệt hoàn toàn xử lý lỗi của Redis (onErrorResume) khỏi downstream chain (chain.filter)
            //    để tránh việc lỗi của downstream bị nuốt thành "Authentication service temporarily unavailable".
            // 3. Nếu key tồn tại trong Redis (token đã bị logout), chặn ngay tại Gateway với 401 Unauthorized.
            // 4. Nếu không bị blacklist, tiếp tục forward request kèm context headers đến downstream service.
            String blacklistKey = BLACKLIST_KEY_PREFIX + jti;
            return redisTemplate.hasKey(blacklistKey)
                    .timeout(Duration.ofMillis(2000))
                    .defaultIfEmpty(false)
                    .onErrorResume(ex -> {
                        log.error("[{}] Error querying Redis blacklist for jti '{}': {}",
                                correlationId, jti, ex.getMessage());
                        return Mono.error(new ResponseStatusException(
                                HttpStatus.INTERNAL_SERVER_ERROR,
                                "Authentication service temporarily unavailable"
                        ));
                    })
                    .flatMap(isBlacklisted -> {
                        if (Boolean.TRUE.equals(isBlacklisted)) {
                            log.warn("[{}] Token with jti '{}' is blacklisted (revoked) for user '{}' on path '{}'",
                                    correlationId, jti, username, path);
                            return writeErrorResponse(
                                    exchange,
                                    HttpStatus.UNAUTHORIZED,
                                    "Token has been revoked",
                                    path
                            );
                        }

                        // Bước 6: Mutate request — gắn User Context headers để downstream service dùng
                        ServerHttpRequest mutatedRequest = request.mutate()
                                .header(CORRELATION_ID_HEADER, correlationId)
                                .header("X-User-Id", username)                     // Tên user (subject của JWT)
                                .header("X-User-Role", primaryRole)                // Role chính của user (STUDENT / INSTRUCTOR)
                                .header("X-User-Roles", String.join(",", roles != null ? roles : List.of()))
                                .header("X-User-Permissions", permissionsJson)     // JSON array chuỗi (PBAC - Bài 6)
                                .build();

                        return chain.filter(exchange.mutate().request(mutatedRequest).build());
                    })
                    .onErrorResume(ResponseStatusException.class, ex ->
                            writeErrorResponse(exchange, HttpStatus.valueOf(ex.getStatusCode().value()), ex.getReason(), path)
                    );

        } catch (ExpiredJwtException ex) {
            // Token hết hạn — trả về 401 với thông báo cụ thể
            log.warn("[{}] Expired JWT for path '{}': {}", correlationId, path, ex.getMessage());
            return writeErrorResponse(exchange, HttpStatus.UNAUTHORIZED, "Token has expired", path);

        } catch (JwtException ex) {
            // Chữ ký sai, token bị tamper, format sai, ...
            log.warn("[{}] Invalid JWT for path '{}': {}", correlationId, path, ex.getMessage());
            return writeErrorResponse(exchange, HttpStatus.UNAUTHORIZED, "Invalid token signature or format", path);

        } catch (IllegalArgumentException ex) {
            // Token là null hoặc chuỗi rỗng
            log.warn("[{}] Empty/null JWT for path '{}': {}", correlationId, path, ex.getMessage());
            return writeErrorResponse(exchange, HttpStatus.UNAUTHORIZED, "Token must not be null or empty", path);
        }
    }

    /**
     * Kiểm tra path hiện tại có khớp với bất kỳ pattern nào trong whitelist không.
     * Sử dụng AntPathMatcher để hỗ trợ wildcard (**, *, ?).
     */
    private boolean isWhitelisted(String path) {
        List<String> whitelistPaths = jwtProperties.getWhitelistPaths();
        if (whitelistPaths == null || whitelistPaths.isEmpty()) {
            return false;
        }
        return whitelistPaths.stream()
                .anyMatch(pattern -> antPathMatcher.match(pattern, path));
    }

    /**
     * Ghi response lỗi dạng JSON ra ServerHttpResponse.
     *
     * Trong WebFlux/Reactive context, không thể dùng Exception handler thông thường
     * như @ControllerAdvice — filter phải tự ghi response và terminate chain.
     *
     * @param exchange  WebExchange hiện tại
     * @param status    HTTP status code (thường là 401)
     * @param message   Thông báo lỗi chi tiết cho client
     * @param path      Đường dẫn request (để đưa vào response body)
     * @return Mono<Void> để kết thúc xử lý
     */
    private Mono<Void> writeErrorResponse(ServerWebExchange exchange,
                                          HttpStatus status,
                                          String message,
                                          String path) {
        ServerHttpResponse response = exchange.getResponse();
        if (response.isCommitted()) {
            return Mono.empty();
        }
        response.setStatusCode(status);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        ErrorResponse errorBody = ErrorResponse.builder()
                .status(status.value())
                .error(status.getReasonPhrase())
                .message(message)
                .path(path)
                .build();

        try {
            byte[] bytes = objectMapper.writeValueAsBytes(errorBody);
            DataBuffer buffer = response.bufferFactory().wrap(bytes);
            return response.writeWith(Mono.just(buffer));
        } catch (JsonProcessingException ex) {
            // Fallback nếu serialization thất bại (hiếm khi xảy ra)
            log.error("Failed to serialize error response: {}", ex.getMessage());
            return response.setComplete();
        }
    }
}
