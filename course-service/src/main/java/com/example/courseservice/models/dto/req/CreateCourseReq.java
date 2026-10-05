package com.example.courseservice.models.dto.req;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Builder;

@Builder
public record CreateCourseReq(
        @NotBlank(message = "Course title is required")
        String title,

        String description,

        @NotBlank(message = "Instructor is required")
        String instructor,

        @NotNull(message = "Duration hours is required")
        @Min(value = 1, message = "Duration must be at least 1 hour")
        Integer durationHours
) {
}
