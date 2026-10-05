package com.example.productservice.models.dto.res;

import com.example.productservice.models.entities.Product;
import lombok.Builder;
import lombok.Getter;

import java.math.BigDecimal;
import java.time.LocalDateTime;

/**
 * DTO trả về thông tin Product cho client.
 * Tách biệt với entity để kiểm soát data exposure.
 */
@Getter
@Builder
public class ProductRes {

    private Long id;
    private String name;
    private String description;
    private BigDecimal price;
    private Integer stock;
    private String category;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    /** Factory method chuyển đổi từ entity sang DTO */
    public static ProductRes fromEntity(Product product) {
        return ProductRes.builder()
                .id(product.getId())
                .name(product.getName())
                .description(product.getDescription())
                .price(product.getPrice())
                .stock(product.getStock())
                .category(product.getCategory())
                .createdAt(product.getCreatedAt())
                .updatedAt(product.getUpdatedAt())
                .build();
    }
}
