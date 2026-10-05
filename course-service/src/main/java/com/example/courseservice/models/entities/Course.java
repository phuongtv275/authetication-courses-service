package com.example.courseservice.models.entities;

import lombok.*;

import java.time.LocalDateTime;

/**
 * Entity Course lưu trữ thông tin khóa học trong bộ nhớ in-memory tĩnh (Thread-safe).
 */
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@Builder
public class Course {
    private Long id;
    private String title;
    private String description;
    private String instructor;
    private Integer durationHours;

    @Builder.Default
    private LocalDateTime createdAt = LocalDateTime.now();

    @Builder.Default
    private LocalDateTime updatedAt = LocalDateTime.now();
}
