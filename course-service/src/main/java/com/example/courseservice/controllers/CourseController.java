package com.example.courseservice.controllers;

import com.example.courseservice.models.dto.req.CreateCourseReq;
import com.example.courseservice.models.dto.res.CourseRes;
import com.example.courseservice.models.services.CourseService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

/**
 * CourseController — REST API quản lý khóa học (Resource Server).
 *
 * Phân quyền dựa trên Spring Security Method Level Security (@PreAuthorize):
 * - GET /api/courses        : Cho phép người dùng có quyền COURSE_READ (hoặc vai trò STUDENT, INSTRUCTOR)
 * - GET /api/courses/{id}   : Cho phép người dùng có quyền COURSE_READ (hoặc vai trò STUDENT, INSTRUCTOR)
 * - POST /api/courses       : CHỈ CHO PHÉP người dùng có quyền COURSE_WRITE (hoặc vai trò INSTRUCTOR)
 */
@Slf4j
@RestController
@RequestMapping("/api/courses")
@RequiredArgsConstructor
public class CourseController {

    private final CourseService courseService;

    /**
     * GET /api/courses — Lấy danh sách khóa học có phân trang (theo quy tắc AGENTS.md).
     * Yêu cầu quyền: COURSE_READ hoặc role STUDENT / INSTRUCTOR.
     */
    @GetMapping
    @PreAuthorize("hasAuthority('COURSE_READ') or hasAuthority('STUDENT') or hasAuthority('INSTRUCTOR')")
    public ResponseEntity<Page<CourseRes>> getAllCourses(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            Authentication authentication
    ) {
        String username = authentication != null ? authentication.getName() : "anonymous";
        log.info("GET /api/courses — user: '{}', authorities: {}", username,
                authentication != null ? authentication.getAuthorities() : "none");

        Pageable pageable = PageRequest.of(page, size);
        return ResponseEntity.ok(courseService.getAllCourses(pageable));
    }

    /**
     * GET /api/courses/{id} — Lấy chi tiết một khóa học.
     * Yêu cầu quyền: COURSE_READ hoặc role STUDENT / INSTRUCTOR.
     */
    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('COURSE_READ') or hasAuthority('STUDENT') or hasAuthority('INSTRUCTOR')")
    public ResponseEntity<CourseRes> getCourseById(
            @PathVariable Long id,
            Authentication authentication
    ) {
        String username = authentication != null ? authentication.getName() : "anonymous";
        log.info("GET /api/courses/{} — user: '{}'", id, username);
        return ResponseEntity.ok(courseService.getCourseById(id));
    }

    /**
     * POST /api/courses — Tạo khóa học mới.
     * Yêu cầu quyền: COURSE_WRITE hoặc role INSTRUCTOR.
     */
    @PostMapping
    @PreAuthorize("hasAuthority('COURSE_WRITE') or hasAuthority('INSTRUCTOR')")
    public ResponseEntity<CourseRes> createCourse(
            @Valid @RequestBody CreateCourseReq req,
            Authentication authentication
    ) {
        String username = authentication != null ? authentication.getName() : "anonymous";
        log.info("POST /api/courses — user: '{}', title: '{}'", username, req.title());
        CourseRes created = courseService.createCourse(req);
        return ResponseEntity.status(HttpStatus.CREATED).body(created);
    }
}
