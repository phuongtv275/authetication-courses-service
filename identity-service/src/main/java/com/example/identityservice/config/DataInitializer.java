package com.example.identityservice.config;

import com.example.identityservice.models.constants.RoleName;
import com.example.identityservice.models.entities.Role;
import com.example.identityservice.models.entities.User;
import com.example.identityservice.models.repositories.RoleRepository;
import com.example.identityservice.models.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Set;

/**
 * Khởi tạo dữ liệu mẫu cho Roles và Users (student, instructor, admin)
 * phục vụ cho việc kiểm thử các bài tập Authentication & Authorization.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class DataInitializer implements CommandLineRunner {

    public static final String DEFAULT_PASSWORD = "password123";

    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) {
        log.info("Checking and initializing seed data for roles and users...");

        // 1. Khởi tạo các Role nếu chưa tồn tại
        Role roleStudent = getOrCreateRole(RoleName.STUDENT);
        Role roleInstructor = getOrCreateRole(RoleName.INSTRUCTOR);
        Role roleUser = getOrCreateRole(RoleName.ROLE_USER);
        Role roleAdmin = getOrCreateRole(RoleName.ROLE_ADMIN);

        // 2. Khởi tạo tài khoản mẫu nếu chưa tồn tại
        // Tài khoản Student (chỉ có quyền COURSE_READ)
        if (userRepository.findByUsername("student").isEmpty()) {
            User student = User.builder()
                    .fullName("Nguyen Van Student")
                    .username("student")
                    .password(passwordEncoder.encode(DEFAULT_PASSWORD))
                    .roles(Set.of(roleStudent))
                    .build();
            userRepository.save(student);
            log.info("Initialized default user: student (Role: STUDENT)");
        }

        // Tài khoản Instructor (có quyền COURSE_READ và COURSE_WRITE)
        if (userRepository.findByUsername("instructor").isEmpty()) {
            User instructor = User.builder()
                    .fullName("Tran Van Instructor")
                    .username("instructor")
                    .password(passwordEncoder.encode(DEFAULT_PASSWORD))
                    .roles(Set.of(roleInstructor))
                    .build();
            userRepository.save(instructor);
            log.info("Initialized default user: instructor (Role: INSTRUCTOR)");
        }

        // Tài khoản Admin
        if (userRepository.findByUsername("admin").isEmpty()) {
            User admin = User.builder()
                    .fullName("Administrator")
                    .username("admin")
                    .password(passwordEncoder.encode(DEFAULT_PASSWORD))
                    .roles(Set.of(roleAdmin))
                    .build();
            userRepository.save(admin);
            log.info("Initialized default user: admin (Role: ROLE_ADMIN)");
        }

        log.info("Seed data initialization completed.");
    }

    private Role getOrCreateRole(RoleName roleName) {
        return roleRepository.findByRoleName(roleName).orElseGet(() -> {
            Role role = Role.builder().roleName(roleName).build();
            return roleRepository.save(role);
        });
    }
}
