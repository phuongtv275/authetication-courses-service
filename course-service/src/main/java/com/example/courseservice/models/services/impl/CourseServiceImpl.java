package com.example.courseservice.models.services.impl;

import com.example.courseservice.exceptions.NotFoundException;
import com.example.courseservice.models.dto.req.CreateCourseReq;
import com.example.courseservice.models.dto.res.CourseRes;
import com.example.courseservice.models.entities.Course;
import com.example.courseservice.models.services.CourseService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;

/**
 * CourseServiceImpl — Quản lý danh sách khóa học hoàn toàn trong bộ nhớ in-memory tĩnh (Thread-safe).
 *
 * Note giải thích logic (theo AGENTS.md và Bài tập 3):
 * 1. Đề bài Bài tập 3 yêu cầu: "Database: KHÔNG (Sử dụng danh sách Java List tĩnh)".
 * 2. Sử dụng CopyOnWriteArrayList để đảm bảo tính an toàn đa luồng (Thread-safety) khi có nhiều request đọc/ghi đồng thời.
 * 3. AtomicLong được dùng để sinh ID duy nhất tự tăng an toàn mà không cần database sequence.
 * 4. Hỗ trợ phân trang chuẩn mực với Pageable (Page, Size) để tuân thủ quy tắc kiến trúc của AGENTS.md.
 */
@Slf4j
@Service
public class CourseServiceImpl implements CourseService {

    private final List<Course> courses = new CopyOnWriteArrayList<>();
    private final AtomicLong idGenerator = new AtomicLong(0);

    public CourseServiceImpl() {
        // Khởi tạo các khóa học mẫu ban đầu
        createInitialCourses();
    }

    private void createInitialCourses() {
        long id1 = idGenerator.incrementAndGet();
        courses.add(Course.builder()
                .id(id1)
                .title("Spring Boot Microservices & Security")
                .description("Master JWT, Gateway, Redis Blacklist and RBAC/PBAC")
                .instructor("Tran Van Instructor")
                .durationHours(40)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build());

        long id2 = idGenerator.incrementAndGet();
        courses.add(Course.builder()
                .id(id2)
                .title("Clean Architecture & SOLID Principles")
                .description("Build scalable and maintainable enterprise software")
                .instructor("Tran Van Instructor")
                .durationHours(30)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build());

        log.info("Initialized {} in-memory sample courses", courses.size());
    }

    @Override
    public Page<CourseRes> getAllCourses(Pageable pageable) {
        log.debug("Fetching all courses with pageable: page={}, size={}", pageable.getPageNumber(), pageable.getPageSize());

        int total = courses.size();
        int start = (int) pageable.getOffset();
        int end = Math.min((start + pageable.getPageSize()), total);

        List<CourseRes> pagedList = new ArrayList<>();
        if (start < total) {
            pagedList = courses.subList(start, end).stream()
                    .map(this::mapToRes)
                    .toList();
        }

        return new PageImpl<>(pagedList, pageable, total);
    }

    @Override
    public CourseRes getCourseById(Long id) {
        log.debug("Fetching course by id: {}", id);
        Course course = courses.stream()
                .filter(c -> c.getId().equals(id))
                .findFirst()
                .orElseThrow(() -> new NotFoundException("Course not found with id: " + id));

        return mapToRes(course);
    }

    @Override
    public CourseRes createCourse(CreateCourseReq req) {
        log.info("Creating new course: title='{}', instructor='{}'", req.title(), req.instructor());

        long newId = idGenerator.incrementAndGet();
        Course course = Course.builder()
                .id(newId)
                .title(req.title().trim())
                .description(req.description() != null ? req.description().trim() : "")
                .instructor(req.instructor().trim())
                .durationHours(req.durationHours())
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();

        courses.add(course);
        log.info("Successfully created course with id: {}", newId);
        return mapToRes(course);
    }

    private CourseRes mapToRes(Course course) {
        return CourseRes.builder()
                .id(course.getId())
                .title(course.getTitle())
                .description(course.getDescription())
                .instructor(course.getInstructor())
                .durationHours(course.getDurationHours())
                .createdAt(course.getCreatedAt())
                .build();
    }
}
