package com.example.productservice.models.services;

import com.example.productservice.models.dto.req.CreateProductReq;
import com.example.productservice.models.dto.req.UpdateProductReq;
import com.example.productservice.models.dto.res.ProductRes;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public interface ProductService {

    /** Lấy danh sách tất cả sản phẩm — có phân trang */
    Page<ProductRes> getAllProducts(Pageable pageable);

    /** Lấy chi tiết một sản phẩm theo ID */
    ProductRes getProductById(Long id);

    /**
     * Tạo mới sản phẩm — CHỈ ADMIN.
     * Yêu cầu: caller phải pass header X-User-Role=ROLE_ADMIN.
     */
    ProductRes createProduct(CreateProductReq req);

    /**
     * Cập nhật sản phẩm — CHỈ ADMIN.
     * Chỉ cập nhật các field không null trong request.
     */
    ProductRes updateProduct(Long id, UpdateProductReq req);

    /** Xoá sản phẩm — CHỈ ADMIN */
    void deleteProduct(Long id);
}
