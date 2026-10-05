package com.example.courseservice.controllers;

import com.example.courseservice.models.dto.req.CreateCourseReq;
import com.example.courseservice.models.dto.res.CourseRes;
import com.example.courseservice.models.services.CourseService;
import com.example.courseservice.security.SecurityConfig;
import com.example.courseservice.security.filter.CorrelationIdFilter;
import com.example.courseservice.security.filter.HeaderAuthenticationFilter;
import com.example.courseservice.security.handler.CustomAccessDeniedHandler;
import com.example.courseservice.security.handler.CustomAuthenticationEntryPoint;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.LocalDateTime;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = CourseController.class)
@Import({
        SecurityConfig.class,
        HeaderAuthenticationFilter.class,
        CorrelationIdFilter.class,
        CustomAuthenticationEntryPoint.class,
        CustomAccessDeniedHandler.class,
        com.example.courseservice.config.JacksonConfig.class
})
class CourseControllerSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private CourseService courseService;

    @Test
    @DisplayName("GET /api/courses without any auth headers should return 401 Unauthorized")
    void shouldReturn401WhenNoHeadersProvided() throws Exception {
        mockMvc.perform(get("/api/courses"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.message").exists());
    }

    @Test
    @DisplayName("GET /api/courses with X-User-Role: STUDENT should return 200 OK (RBAC - Bài 3)")
    void shouldAllowStudentRoleToGetCourses() throws Exception {
        CourseRes course = CourseRes.builder()
                .id(1L)
                .title("Spring Boot")
                .instructor("Instructor A")
                .durationHours(20)
                .createdAt(LocalDateTime.now())
                .build();
        Pageable pageable = org.springframework.data.domain.PageRequest.of(0, 10);
        when(courseService.getAllCourses(any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of(course), pageable, 1));

        mockMvc.perform(get("/api/courses")
                        .header("X-User-Id", "student_alice")
                        .header("X-User-Role", "STUDENT"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[0].title").value("Spring Boot"));

        verify(courseService).getAllCourses(any(Pageable.class));
    }

    @Test
    @DisplayName("GET /api/courses with X-User-Permissions: [\"COURSE_READ\"] should return 200 OK (PBAC - Bài 6)")
    void shouldAllowCourseReadPermissionToGetCourses() throws Exception {
        CourseRes course = CourseRes.builder()
                .id(1L)
                .title("Spring Boot")
                .instructor("Instructor A")
                .durationHours(20)
                .createdAt(LocalDateTime.now())
                .build();
        Pageable pageable = org.springframework.data.domain.PageRequest.of(0, 10);
        when(courseService.getAllCourses(any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of(course), pageable, 1));

        mockMvc.perform(get("/api/courses")
                        .header("X-User-Id", "student_alice")
                        .header("X-User-Permissions", "[\"COURSE_READ\"]"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[0].title").value("Spring Boot"));

        verify(courseService).getAllCourses(any(Pageable.class));
    }

    @Test
    @DisplayName("POST /api/courses with X-User-Role: STUDENT should return 403 Forbidden (RBAC - Bài 3)")
    void shouldDenyStudentRoleFromCreatingCourse() throws Exception {
        CreateCourseReq req = new CreateCourseReq(
                "Golang Backend",
                "Learn Go from scratch",
                "Alice",
                20
        );

        mockMvc.perform(post("/api/courses")
                        .header("X-User-Id", "student_alice")
                        .header("X-User-Role", "STUDENT")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.status").value(403));

        verify(courseService, never()).createCourse(any());
    }

    @Test
    @DisplayName("POST /api/courses with X-User-Permissions: [\"COURSE_READ\"] should return 403 Forbidden (PBAC - Bài 6)")
    void shouldDenyCourseReadPermissionFromCreatingCourse() throws Exception {
        CreateCourseReq req = new CreateCourseReq(
                "Golang Backend",
                "Learn Go from scratch",
                "Alice",
                20
        );

        mockMvc.perform(post("/api/courses")
                        .header("X-User-Id", "student_alice")
                        .header("X-User-Permissions", "[\"COURSE_READ\"]")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.status").value(403));

        verify(courseService, never()).createCourse(any());
    }

    @Test
    @DisplayName("POST /api/courses with X-User-Role: INSTRUCTOR should return 201 Created (RBAC - Bài 3)")
    void shouldAllowInstructorRoleToCreateCourse() throws Exception {
        CreateCourseReq req = new CreateCourseReq(
                "Kubernetes for Developers",
                "Deploy and scale microservices with K8s",
                "Bob Instructor",
                35
        );
        CourseRes res = CourseRes.builder()
                .id(1L)
                .title("Kubernetes for Developers")
                .instructor("Bob Instructor")
                .durationHours(35)
                .createdAt(LocalDateTime.now())
                .build();
        when(courseService.createCourse(any(CreateCourseReq.class))).thenReturn(res);

        mockMvc.perform(post("/api/courses")
                        .header("X-User-Id", "instructor_bob")
                        .header("X-User-Role", "INSTRUCTOR")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").value(1))
                .andExpect(jsonPath("$.title").value("Kubernetes for Developers"));

        verify(courseService).createCourse(any(CreateCourseReq.class));
    }

    @Test
    @DisplayName("POST /api/courses with X-User-Permissions: [\"COURSE_READ\", \"COURSE_WRITE\"] should return 201 Created (PBAC - Bài 6)")
    void shouldAllowCourseWritePermissionToCreateCourse() throws Exception {
        CreateCourseReq req = new CreateCourseReq(
                "Event-Driven Architecture with Kafka",
                "Master messaging and stream processing",
                "Bob Instructor",
                25
        );
        CourseRes res = CourseRes.builder()
                .id(2L)
                .title("Event-Driven Architecture with Kafka")
                .instructor("Bob Instructor")
                .durationHours(25)
                .createdAt(LocalDateTime.now())
                .build();
        when(courseService.createCourse(any(CreateCourseReq.class))).thenReturn(res);

        mockMvc.perform(post("/api/courses")
                        .header("X-User-Id", "instructor_bob")
                        .header("X-User-Permissions", "[\"COURSE_READ\", \"COURSE_WRITE\"]")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").value(2))
                .andExpect(jsonPath("$.title").value("Event-Driven Architecture with Kafka"));

        verify(courseService).createCourse(any(CreateCourseReq.class));
    }

    @Test
    @DisplayName("POST /api/courses with invalid request DTO should return 400 Bad Request")
    void shouldReturn400WhenValidationFails() throws Exception {
        CreateCourseReq invalidReq = new CreateCourseReq(
                "", // Blank title violates @NotBlank
                "Description",
                "", // Blank instructor violates @NotBlank
                0   // Duration < 1 violates @Min(1)
        );

        mockMvc.perform(post("/api/courses")
                        .header("X-User-Id", "instructor_bob")
                        .header("X-User-Permissions", "[\"COURSE_WRITE\"]")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidReq)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.details").isMap());
    }
}
