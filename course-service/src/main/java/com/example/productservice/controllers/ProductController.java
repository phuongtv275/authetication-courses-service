package com.example.productservice.controllers;

import com.example.productservice.models.dto.req.CreateProductReq;
import com.example.productservice.models.dto.req.UpdateProductReq;
import com.example.productservice.models.dto.res.ProductRes;
import com.example.productservice.models.services.ProductService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

/**
 * ProductController — CRUD API cho Product Service (Resource Server).
 *
 * Phân quyền dựa trên Spring Security Method Level Security (@PreAuthorize):
 * - GET /api/products        : Cho phép mọi user đã xác thực (USER, ADMIN)
 * - GET /api/products/{id}   : Cho phép mọi user đã xác thực (USER, ADMIN)
 * - POST /api/products        : CHỈ User có quyền ROLE_ADMIN
 * - PUT /api/products/{id}    : CHỈ User có quyền ROLE_ADMIN
 * - DELETE /api/products/{id} : CHỈ User có quyền ROLE_ADMIN
 */
@Slf4j
@RestController
@RequestMapping("/api/products")
@RequiredArgsConstructor
public class ProductController {

    private final ProductService productService;

    /**
     * GET /api/products — Lấy danh sách sản phẩm có phân trang.
     * Mọi người dùng đã xác thực (ROLE_USER, ROLE_ADMIN) đều có thể truy cập.
     */
    @GetMapping
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public ResponseEntity<Page<ProductRes>> getAllProducts(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(defaultValue = "id") String sortBy,
            @RequestParam(defaultValue = "asc") String sortDir,
            Authentication authentication
    ) {
        log.debug("GET /api/products — user: '{}'", authentication != null ? authentication.getName() : "anonymous");
        Sort sort = sortDir.equalsIgnoreCase("desc") ? Sort.by(sortBy).descending() : Sort.by(sortBy).ascending();
        Pageable pageable = PageRequest.of(page, size, sort);
        return ResponseEntity.ok(productService.getAllProducts(pageable));
    }

    /**
     * GET /api/products/{id} — Lấy chi tiết một sản phẩm.
     * Mọi người dùng đã xác thực đều có thể truy cập.
     */
    @GetMapping("/{id}")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public ResponseEntity<ProductRes> getProductById(
            @PathVariable Long id,
            Authentication authentication
    ) {
        log.debug("GET /api/products/{} — user: '{}'", id, authentication != null ? authentication.getName() : "anonymous");
        return ResponseEntity.ok(productService.getProductById(id));
    }

    /**
     * POST /api/products — Tạo sản phẩm mới.
     * CHỈ CHO PHÉP ROLE_ADMIN.
     */
    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ProductRes> createProduct(
            @Valid @RequestBody CreateProductReq req,
            Authentication authentication
    ) {
        log.info("POST /api/products — admin: '{}', product: '{}'",
                authentication != null ? authentication.getName() : "unknown", req.name());
        ProductRes created = productService.createProduct(req);
        return ResponseEntity.status(HttpStatus.CREATED).body(created);
    }

    /**
     * PUT /api/products/{id} — Cập nhật sản phẩm.
     * CHỈ CHO PHÉP ROLE_ADMIN.
     */
    @PutMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ProductRes> updateProduct(
            @PathVariable Long id,
            @Valid @RequestBody UpdateProductReq req,
            Authentication authentication
    ) {
        log.info("PUT /api/products/{} — admin: '{}'",
                id, authentication != null ? authentication.getName() : "unknown");
        return ResponseEntity.ok(productService.updateProduct(id, req));
    }

    /**
     * DELETE /api/products/{id} — Xoá sản phẩm.
     * CHỈ CHO PHÉP ROLE_ADMIN.
     */
    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> deleteProduct(
            @PathVariable Long id,
            Authentication authentication
    ) {
        log.info("DELETE /api/products/{} — admin: '{}'",
                id, authentication != null ? authentication.getName() : "unknown");
        productService.deleteProduct(id);
        return ResponseEntity.noContent().build();
    }
}
