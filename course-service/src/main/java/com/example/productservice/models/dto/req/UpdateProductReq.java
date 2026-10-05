package com.example.productservice.models.dto.req;

import jakarta.validation.constraints.*;

import java.math.BigDecimal;

/**
 * DTO nhận dữ liệu khi cập nhật Product.
 * Tất cả field đều optional (null = không cập nhật field đó).
 */
public record UpdateProductReq(

        @Size(max = 255, message = "Product name must not exceed 255 characters")
        String name,

        String description,

        @DecimalMin(value = "0.0", inclusive = false, message = "Price must be greater than 0")
        @Digits(integer = 13, fraction = 2, message = "Price format invalid")
        BigDecimal price,

        @Min(value = 0, message = "Stock must not be negative")
        Integer stock,

        String category
) {}
