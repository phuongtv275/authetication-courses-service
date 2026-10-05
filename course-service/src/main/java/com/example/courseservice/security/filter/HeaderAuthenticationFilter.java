package com.example.courseservice.security.filter;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * HeaderAuthenticationFilter — Bộ lọc xác thực và chuyển đổi quyền từ API Gateway.
 *
 * Note giải thích logic (theo AGENTS.md, Bài tập 3 và Bài tập 6):
 * 1. Resource Server Course-Service hoạt động sau Gateway nên không parse lại token JWT.
 * 2. Yêu cầu bắt buộc header X-User-Id để định danh danh tính người dùng. Nếu không có X-User-Id,
 *    không nạp Authentication để Spring Security xử lý 401 Unauthorized.
 * 3. Ưu tiên phân quyền theo Hành động (PBAC - Bài 6): Đọc X-User-Permissions (JSON array chuỗi).
 *    Nếu có X-User-Permissions, chuyển đổi thành các GrantedAuthority tương ứng (COURSE_READ, COURSE_WRITE,...).
 * 4. Nếu không có X-User-Permissions (hỗ trợ chuyển giao RBAC - Bài 3), fallback đọc X-User-Role / X-User-Roles.
 * 5. Log đầy đủ correlationId để phục vụ việc trace lỗi xuyên suốt các services.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class HeaderAuthenticationFilter extends OncePerRequestFilter {

    public static final String HEADER_USER_ID = "X-User-Id";
    public static final String HEADER_USER_ROLE = "X-User-Role";
    public static final String HEADER_USER_ROLES = "X-User-Roles";
    public static final String HEADER_USER_PERMISSIONS = "X-User-Permissions";

    private final ObjectMapper objectMapper;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String correlationId = MDC.get("correlationId");
        String userId = request.getHeader(HEADER_USER_ID);
        String permissionsJson = request.getHeader(HEADER_USER_PERMISSIONS);
        String singleRole = request.getHeader(HEADER_USER_ROLE);
        String multiRoles = request.getHeader(HEADER_USER_ROLES);

        // Bắt buộc phải có X-User-Id để xác định danh tính hợp lệ từ Gateway
        if (StringUtils.hasText(userId)) {
            Set<SimpleGrantedAuthority> authorities = new HashSet<>();

            // 1. PBAC (Bài 6): Đọc permissions từ chuỗi JSON
            boolean hasPermissions = false;
            if (StringUtils.hasText(permissionsJson)) {
                try {
                    List<String> permissions = objectMapper.readValue(permissionsJson, new TypeReference<List<String>>() {});
                    if (permissions != null && !permissions.isEmpty()) {
                        for (String perm : permissions) {
                            if (StringUtils.hasText(perm)) {
                                authorities.add(new SimpleGrantedAuthority(perm.trim()));
                            }
                        }
                        hasPermissions = true;
                    }
                } catch (Exception e) {
                    log.warn("[{}] Failed to parse X-User-Permissions JSON (length={}): {}",
                            correlationId, permissionsJson.length(), e.getMessage());
                }
            }

            // 2. Fallback sang RBAC (Bài 3) nếu không có permissions header
            if (!hasPermissions) {
                String role = StringUtils.hasText(singleRole) ? singleRole : multiRoles;
                if (StringUtils.hasText(role)) {
                    if (role.contains("INSTRUCTOR") || role.contains("ADMIN")) {
                        authorities.add(new SimpleGrantedAuthority("COURSE_READ"));
                        authorities.add(new SimpleGrantedAuthority("COURSE_WRITE"));
                    } else if (role.contains("STUDENT") || role.contains("USER")) {
                        authorities.add(new SimpleGrantedAuthority("COURSE_READ"));
                    }
                }
            }

            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(userId.trim(), null, authorities);
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            SecurityContextHolder.getContext().setAuthentication(authentication);
            log.debug("[{}] Successfully authenticated request from Gateway — user: '{}', authorities: {}",
                    correlationId, userId, authorities);
        }

        filterChain.doFilter(request, response);
    }

    private void addRoleAuthorities(Set<SimpleGrantedAuthority> authorities, String role) {
        if (!StringUtils.hasText(role)) {
            return;
        }
        authorities.add(new SimpleGrantedAuthority(role));
        if (!role.startsWith("ROLE_")) {
            authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
        }
    }
}
