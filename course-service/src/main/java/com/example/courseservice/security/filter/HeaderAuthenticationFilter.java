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
 * HeaderAuthenticationFilter — Bộ lọc xác thực và nạp quyền PBAC từ API Gateway (Bài tập 6).
 *
 * Note giải thích logic (theo AGENTS.md và Bài tập 6):
 * 1. Chuyển đổi mô hình phân quyền sang PBAC thuần túy (Permission-Based Access Control).
 * 2. Yêu cầu bắt buộc header X-User-Id để nhận diện người dùng. Nếu thiếu X-User-Id, không nạp
 *    Authentication (request không được xác thực, trả 401 Unauthorized khi truy cập endpoint cần bảo vệ).
 * 3. Quyền hạn (Authorities) CHỈ được cấp phát từ claim X-User-Permissions (JSON array chuỗi).
 *    Tuyệt đối không cấp quyền dựa trên Role (tránh việc bypass PBAC khi user mang role nhưng không có quyền ghi).
 * 4. Nếu X-User-Permissions rỗng, là "[]", bị thiếu hoặc JSON bị lỗi cú pháp, authorities của user sẽ là rỗng (Empty),
 *    dẫn đến 403 Forbidden khi thực hiện bất kỳ hành vi nào đòi hỏi quyền hạn.
 * 5. Log đầy đủ correlationId để phục vụ việc trace lỗi xuyên suốt hệ thống.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class HeaderAuthenticationFilter extends OncePerRequestFilter {

    public static final String HEADER_USER_ID = "X-User-Id";
    public static final String HEADER_USER_PERMISSIONS = "X-User-Permissions";

    private final ObjectMapper objectMapper;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String correlationId = MDC.get("correlationId");
        String userId = request.getHeader(HEADER_USER_ID);
        String permissionsJson = request.getHeader(HEADER_USER_PERMISSIONS);

        // Bắt buộc phải có X-User-Id để xác định danh tính hợp lệ từ Gateway
        if (StringUtils.hasText(userId)) {
            Set<SimpleGrantedAuthority> authorities = new HashSet<>();

            // PBAC (Bài 6): Đọc quyền hạn cụ thể duy nhất từ header X-User-Permissions
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
                    log.warn("[{}] Failed to parse X-User-Permissions JSON (length={}): {}",
                            correlationId, permissionsJson.length(), e.getMessage());
                }
            }

            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(userId.trim(), null, authorities);
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            SecurityContextHolder.getContext().setAuthentication(authentication);
            log.debug("[{}] Authenticated PBAC request from Gateway — user: '{}', authorities: {}",
                    correlationId, userId, authorities);
        }

        filterChain.doFilter(request, response);
    }
}
