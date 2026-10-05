package com.example.courseservice.models.dto.res;

import lombok.Builder;

import java.time.LocalDateTime;

@Builder
public record CourseRes(
        Long id,
        String title,
        String description,
        String instructor,
        Integer durationHours,
        LocalDateTime createdAt
) {
}
