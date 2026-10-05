package com.example.identityservice.security.permission;

import com.example.identityservice.models.constants.RoleName;
import com.example.identityservice.models.entities.Role;
import com.example.identityservice.models.entities.User;
import org.springframework.stereotype.Component;

import java.util.*;

/**
 * Component phân giải quyền (Permissions) và Vai trò (Role) chính xác từ User.
 * Tuân thủ nguyên lý Đơn trách nhiệm (SRP) và Mở rộng (OCP).
 */
@Component
public class PermissionResolver {

    public static final String PERMISSION_COURSE_READ = "COURSE_READ";
    public static final String PERMISSION_COURSE_WRITE = "COURSE_WRITE";

    private static final Map<RoleName, Set<String>> ROLE_PERMISSIONS = Map.of(
            RoleName.INSTRUCTOR, Set.of(PERMISSION_COURSE_READ, PERMISSION_COURSE_WRITE),
            RoleName.ROLE_ADMIN, Set.of(PERMISSION_COURSE_READ, PERMISSION_COURSE_WRITE),
            RoleName.STUDENT, Set.of(PERMISSION_COURSE_READ),
            RoleName.ROLE_USER, Set.of(PERMISSION_COURSE_READ)
    );

    /**
     * Phân giải danh sách permissions từ các roles của người dùng (PBAC - Bài 6).
     */
    public List<String> resolvePermissions(User user) {
        if (user == null || user.getRoles() == null) {
            return List.of();
        }
        Set<String> perms = new LinkedHashSet<>();
        for (Role role : user.getRoles()) {
            if (role != null && role.getRoleName() != null) {
                Set<String> mapped = ROLE_PERMISSIONS.get(role.getRoleName());
                if (mapped != null) {
                    perms.addAll(mapped);
                }
            }
        }
        return new ArrayList<>(perms);
    }

    /**
     * Phân giải Role chính theo thứ tự ưu tiên (RBAC - Bài 1, Bài 2).
     */
    public String resolvePrimaryRole(User user) {
        if (user == null || user.getRoles() == null || user.getRoles().isEmpty()) {
            return "";
        }
        Set<RoleName> roleNames = new HashSet<>();
        for (Role role : user.getRoles()) {
            if (role != null && role.getRoleName() != null) {
                roleNames.add(role.getRoleName());
            }
        }
        if (roleNames.contains(RoleName.INSTRUCTOR)) return "INSTRUCTOR";
        if (roleNames.contains(RoleName.STUDENT)) return "STUDENT";
        if (roleNames.contains(RoleName.ROLE_ADMIN)) return "ROLE_ADMIN";
        if (roleNames.contains(RoleName.ROLE_USER)) return "ROLE_USER";
        return user.getRoles().iterator().next().getRoleName().name();
    }
}
