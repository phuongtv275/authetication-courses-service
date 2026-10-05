package com.example.courseservice.security.filter;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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
 * HeaderAuthenticationFilter — Bộ lọc xác thực trực tiếp qua HTTP Headers từ API Gateway.
 *
 * Note giải thích logic (theo AGENTS.md, Bài tập 3 và Bài tập 6):
 * 1. Course Service đóng vai trò Resource Server phía sau API Gateway.
 * 2. Resource Server KHÔNG cần thư viện JJWT hay Secret Key để giải mã lại JWT, vì Gateway đã đóng vai trò
 *    "Trạm gác biên phòng" kiểm tra chữ ký và Redis Blacklist trước khi chuyển tiếp request.
 * 3. Filter này đọc trực tiếp:
 *    - X-User-Id: định danh người dùng (subject / username).
 *    - X-User-Role / X-User-Roles: vai trò người dùng (STUDENT, INSTRUCTOR, ...).
 *    - X-User-Permissions: chuỗi JSON chứa danh sách quyền (PBAC: ["COURSE_READ", "COURSE_WRITE"]).
 * 4. Chuyển đổi toàn bộ quyền (Permissions) và vai trò (Roles) thành SimpleGrantedAuthority để Spring Security
 *    Method Security (@PreAuthorize) phân quyền chính xác.
 * 5. Nếu không có header nhận diện người dùng hoặc danh sách quyền rỗng, không nạp Authentication,
 *    Spring Security sẽ tự động trả về 401 Unauthorized qua CustomAuthenticationEntryPoint.
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

        String userId = request.getHeader(HEADER_USER_ID);
        String permissionsJson = request.getHeader(HEADER_USER_PERMISSIONS);
        String singleRole = request.getHeader(HEADER_USER_ROLE);
        String multiRoles = request.getHeader(HEADER_USER_ROLES);

        // Nếu có ít nhất một thông tin nhận diện người dùng hoặc quyền từ Gateway
        if (StringUtils.hasText(userId) || StringUtils.hasText(permissionsJson) || StringUtils.hasText(singleRole)) {
            Set<SimpleGrantedAuthority> authorities = new HashSet<>();

            // 1. Phân giải Permissions từ Header JSON (PBAC - Bài 6)
            if (StringUtils.hasText(permissionsJson)) {
                try {
                    List<String> permissions = objectMapper.readValue(permissionsJson, new TypeReference<List<String>>() {});
                    if (permissions != null) {
                        for (String perm : permissions) {
                            if (StringUtils.hasText(perm)) {
                                authorities.add(new SimpleGrantedAuthority(perm.trim()));
                            }
                        }
                    }
                } catch (Exception e) {
                    log.warn("Failed to parse X-User-Permissions JSON '{}': {}", permissionsJson, e.getMessage());
                }
            }

            // 2. Phân giải Roles từ Header (RBAC - Bài 3)
            if (StringUtils.hasText(multiRoles)) {
                for (String role : multiRoles.split(",")) {
                    addRoleAuthorities(authorities, role.trim());
                }
            } else if (StringUtils.hasText(singleRole)) {
                addRoleAuthorities(authorities, singleRole.trim());
            }

            String principal = StringUtils.hasText(userId) ? userId : "gateway-user";
            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(principal, null, authorities);
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            SecurityContextHolder.getContext().setAuthentication(authentication);
            log.debug("Authenticated request from Gateway — user: '{}', authorities: {}", principal, authorities);
        }

        filterChain.doFilter(request, response);
    }

    private void addRoleAuthorities(Set<SimpleGrantedAuthority> authorities, String role) {
        if (!StringUtils.hasText(role)) {
            return;
        }
        // Thêm cả dạng nguyên bản (hasAuthority('STUDENT')) và tiền tố ROLE_ (hasRole('STUDENT'))
        authorities.add(new SimpleGrantedAuthority(role));
        if (!role.startsWith("ROLE_")) {
            authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
        }
    }
}
