package com.example.courseservice.models.services;

import com.example.courseservice.models.dto.req.CreateCourseReq;
import com.example.courseservice.models.dto.res.CourseRes;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public interface CourseService {
    Page<CourseRes> getAllCourses(Pageable pageable);
    CourseRes getCourseById(Long id);
    CourseRes createCourse(CreateCourseReq req);
}
