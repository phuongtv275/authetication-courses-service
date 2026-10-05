package com.example.courseservice.controllers;

import com.example.courseservice.models.dto.req.CreateCourseReq;
import com.example.courseservice.models.dto.res.CourseRes;
import com.example.courseservice.models.dto.res.PageResponse;
import com.example.courseservice.models.services.CourseService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

/**
 * CourseController — REST API quản lý khóa học theo mô hình PBAC (Bài tập 6).
 *
 * Phân quyền dựa trên Spring Security Method Level Security (@PreAuthorize):
 * - GET /api/courses        : Yêu cầu quyền COURSE_READ
 * - GET /api/courses/{id}   : Yêu cầu quyền COURSE_READ
 * - POST /api/courses       : Yêu cầu quyền COURSE_WRITE
 */
@Slf4j
@Validated
@RestController
@RequestMapping("/api/courses")
@RequiredArgsConstructor
public class CourseController {

    private final CourseService courseService;

    /**
     * GET /api/courses — Lấy danh sách khóa học có phân trang (theo quy tắc AGENTS.md).
     * Yêu cầu quyền: COURSE_READ.
     * Validate tham số phân trang: page >= 0, 1 <= size <= 100.
     */
    @GetMapping
    @PreAuthorize("hasAuthority('COURSE_READ')")
    public ResponseEntity<PageResponse<CourseRes>> getAllCourses(
            @RequestParam(defaultValue = "0") @Min(value = 0, message = "Page index must not be less than 0") int page,
            @RequestParam(defaultValue = "10") @Min(value = 1, message = "Page size must be at least 1")
            @Max(value = 100, message = "Page size must not exceed 100") int size,
            Authentication authentication
    ) {
        String username = authentication != null ? authentication.getName() : "anonymous";
        log.info("GET /api/courses — user: '{}', page: {}, size: {}", username, page, size);

        Pageable pageable = PageRequest.of(page, size);
        Page<CourseRes> coursePage = courseService.getAllCourses(pageable);
        return ResponseEntity.ok(PageResponse.from(coursePage));
    }

    /**
     * GET /api/courses/{id} — Lấy chi tiết một khóa học.
     * Yêu cầu quyền: COURSE_READ.
     */
    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('COURSE_READ')")
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
     * Yêu cầu quyền: COURSE_WRITE.
     */
    @PostMapping
    @PreAuthorize("hasAuthority('COURSE_WRITE')")
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
