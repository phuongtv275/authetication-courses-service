package com.example.productservice.models.dto.req;

import jakarta.validation.constraints.*;

import java.math.BigDecimal;

/**
 * DTO nhận dữ liệu khi tạo mới Product.
 * Dùng Record để immutable và tự sinh constructor/getter.
 */
public record CreateProductReq(

        @NotBlank(message = "Product name must not be blank")
        @Size(max = 255, message = "Product name must not exceed 255 characters")
        String name,

        String description,

        @NotNull(message = "Price is required")
        @DecimalMin(value = "0.0", inclusive = false, message = "Price must be greater than 0")
        @Digits(integer = 13, fraction = 2, message = "Price format invalid")
        BigDecimal price,

        @NotNull(message = "Stock is required")
        @Min(value = 0, message = "Stock must not be negative")
        Integer stock,

        @NotBlank(message = "Category must not be blank")
        String category
) {}
