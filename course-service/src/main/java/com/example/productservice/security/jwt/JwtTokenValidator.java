package com.example.productservice.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * Validator và parser JWT cho Downstream Service (Product-Service).
 * Sử dụng chung Secret Key với Identity-Service và API Gateway.
 */
@Slf4j
@Component
public class JwtTokenValidator {

    @Value("${app.jwt.secret}")
    private String secretKey;

    private Key signKey;

    @PostConstruct
    public void init() {
        byte[] bytes = Decoders.BASE64.decode(secretKey);
        this.signKey = Keys.hmacShaKeyFor(bytes);
        log.info("JwtTokenValidator initialized successfully with HMAC-SHA256 key");
    }

    public Key getSignKey() {
        if (this.signKey == null) {
            init();
        }
        return this.signKey;
    }

    /**
     * Phân tích và xác thực token JWT trong một lần duy nhất (Single-pass parse & verify).
     *
     * @param token chuỗi JWT
     * @return Optional chứa Claims nếu hợp lệ, Optional.empty() nếu token sai chữ ký hoặc hết hạn
     */
    public Optional<Claims> parseAndValidateClaims(String token) {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(getSignKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
            return Optional.of(claims);
        } catch (JwtException | IllegalArgumentException e) {
            log.warn("Invalid JWT token: {}", e.getMessage());
            return Optional.empty();
        }
    }

    /**
     * Trích xuất username từ Claims đã được xác thực.
     */
    public String extractUsername(Claims claims) {
        String username = claims.get("username", String.class);
        return username != null ? username : claims.getSubject();
    }

    /**
     * Trích xuất danh sách vai trò (roles) từ Claims đã được xác thực.
     */
    @SuppressWarnings("unchecked")
    public List<String> extractRoles(Claims claims) {
        Object rolesObj = claims.get("roles");
        if (rolesObj instanceof List<?>) {
            return ((List<?>) rolesObj).stream()
                    .map(Object::toString)
                    .toList();
        }
        return Collections.emptyList();
    }

    /**
     * Xác thực tính hợp lệ và chữ ký của chuỗi token.
     *
     * @param token chuỗi JWT
     * @return true nếu token hợp lệ, false nếu hết hạn hoặc sai chữ ký
     */
    public boolean validateToken(String token) {
        return parseAndValidateClaims(token).isPresent();
    }

    /**
     * Trích xuất toàn bộ Claims từ token JWT hợp lệ.
     *
     * @param token chuỗi JWT
     * @return đối tượng Claims
     */
    public Claims getClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * Trích xuất username (subject) từ token.
     */
    public String getUsername(String token) {
        return parseAndValidateClaims(token)
                .map(this::extractUsername)
                .orElse(null);
    }

    /**
     * Trích xuất danh sách vai trò (roles) từ Claims.
     */
    public List<String> getRoles(String token) {
        return parseAndValidateClaims(token)
                .map(this::extractRoles)
                .orElse(Collections.emptyList());
    }
}
