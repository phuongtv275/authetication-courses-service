package com.example.identityservice.security.jwt;


import com.example.identityservice.models.entities.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import io.jsonwebtoken.ExpiredJwtException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Slf4j
@Component
public class JwtUtils {
    @Value("${app.jwt.secret}")
    private String secretKey;

    @Value("${app.jwt.access-token-expiration:900000}")
    private Long accessTokenExpiration;

    private Key signKey;

    @PostConstruct
    public void init() {
        byte[] bytes = Decoders.BASE64.decode(secretKey);
        this.signKey = Keys.hmacShaKeyFor(bytes);
    }

    // Lấy signing key từ Base64 secret (HMAC-SHA256 >= 256 bits)
    public Key getSignKey() {
        if (this.signKey == null) {
            init();
        }
        return this.signKey;
    }

    private final com.example.identityservice.security.permission.PermissionResolver permissionResolver;

    @org.springframework.beans.factory.annotation.Autowired
    public JwtUtils(com.example.identityservice.security.permission.PermissionResolver permissionResolver) {
        this.permissionResolver = permissionResolver;
    }

    public JwtUtils() {
        this(new com.example.identityservice.security.permission.PermissionResolver());
    }

    /**
     * Tạo Access Token (JWT) ngắn hạn chứa thông tin người dùng, vai trò (role/roles),
     * quyền hạn chi tiết (permissions - PBAC) và claim định danh duy nhất jti (JWT ID).
     *
     * @param user đối tượng User chứa thông tin tài khoản và danh sách quyền
     * @return chuỗi JWT Access Token
     */
    public String generateAccessToken(User user) {
        List<String> roleNames = user.getRoles() != null
                ? user.getRoles().stream()
                    .map(role -> role.getRoleName().name())
                    .toList()
                : List.of();

        String jti = UUID.randomUUID().toString();
        String primaryRole = permissionResolver.resolvePrimaryRole(user);
        List<String> permissions = permissionResolver.resolvePermissions(user);

        Map<String, Object> claims = new HashMap<>();
        claims.put("username", user.getUsername());
        claims.put("role", primaryRole);
        claims.put("roles", roleNames);
        claims.put("permissions", permissions);
        claims.put(Claims.ID, jti);

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(user.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + accessTokenExpiration))
                .signWith(getSignKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    // Giữ lại generateToken để tương thích ngược
    public String generateToken(User user) {
        return generateAccessToken(user);
    }

    /**
     * Giải mã toàn bộ Claims từ chuỗi JWT.
     * Cho phép lấy claims ngay cả khi token đã hết hạn tự nhiên (ExpiredJwtException).
     */
    public Claims extractAllClaims(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(getSignKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (ExpiredJwtException e) {
            log.debug("Token has expired, returning claims from ExpiredJwtException: {}", e.getMessage());
            return e.getClaims();
        }
    }

    /**
     * Trích xuất claim jti (JWT ID).
     */
    public String extractJti(String token) {
        return extractAllClaims(token).getId();
    }

    /**
     * Trích xuất thời điểm hết hạn (exp).
     */
    public Date extractExpiration(String token) {
        return extractAllClaims(token).getExpiration();
    }

    /**
     * Trích xuất username (subject).
     */
    public String extractUsername(String token) {
        return extractAllClaims(token).getSubject();
    }

    /**
     * Trích xuất role từ token.
     */
    public String extractRole(String token) {
        Object role = extractAllClaims(token).get("role");
        return role != null ? role.toString() : null;
    }

    /**
     * Trích xuất danh sách roles từ token.
     */
    @SuppressWarnings("unchecked")
    public List<String> extractRoles(String token) {
        Object roles = extractAllClaims(token).get("roles");
        if (roles instanceof List<?>) {
            return (List<String>) roles;
        }
        return List.of();
    }

    /**
     * Trích xuất danh sách permissions từ token.
     */
    @SuppressWarnings("unchecked")
    public List<String> extractPermissions(String token) {
        Object permissions = extractAllClaims(token).get("permissions");
        if (permissions instanceof List<?>) {
            return (List<String>) permissions;
        }
        return List.of();
    }

    /**
     * Kiểm tra tính hợp lệ về chữ ký và hạn dùng của token.
     */
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(getSignKey())
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
