package com.example.productservice.models.services.impl;

import com.example.productservice.exceptions.NotFoundException;
import com.example.productservice.models.dto.req.CreateProductReq;
import com.example.productservice.models.dto.req.UpdateProductReq;
import com.example.productservice.models.dto.res.ProductRes;
import com.example.productservice.models.entities.Product;
import com.example.productservice.models.repositories.ProductRepository;
import com.example.productservice.models.services.ProductService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class ProductServiceImpl implements ProductService {

    private final ProductRepository productRepository;

    @Override
    @Transactional(readOnly = true)
    public Page<ProductRes> getAllProducts(Pageable pageable) {
        log.debug("Fetching all products — page: {}, size: {}", pageable.getPageNumber(), pageable.getPageSize());
        return productRepository.findAll(pageable).map(ProductRes::fromEntity);
    }

    @Override
    @Transactional(readOnly = true)
    public ProductRes getProductById(Long id) {
        log.debug("Fetching product by id: {}", id);
        Product product = findProductOrThrow(id);
        return ProductRes.fromEntity(product);
    }

    @Override
    @Transactional
    public ProductRes createProduct(CreateProductReq req) {
        log.info("Creating new product: name='{}', category='{}'", req.name(), req.category());

        Product product = Product.builder()
                .name(req.name())
                .description(req.description())
                .price(req.price())
                .stock(req.stock())
                .category(req.category())
                .build();

        Product saved = productRepository.save(product);
        log.info("Product created successfully with id: {}", saved.getId());
        return ProductRes.fromEntity(saved);
    }

    @Override
    @Transactional
    public ProductRes updateProduct(Long id, UpdateProductReq req) {
        log.info("Updating product id: {}", id);
        Product product = findProductOrThrow(id);

        // Chỉ cập nhật các field không null — partial update
        if (req.name() != null) product.setName(req.name());
        if (req.description() != null) product.setDescription(req.description());
        if (req.price() != null) product.setPrice(req.price());
        if (req.stock() != null) product.setStock(req.stock());
        if (req.category() != null) product.setCategory(req.category());

        Product saved = productRepository.save(product);
        log.info("Product id: {} updated successfully", id);
        return ProductRes.fromEntity(saved);
    }

    @Override
    @Transactional
    public void deleteProduct(Long id) {
        log.info("Deleting product id: {}", id);
        findProductOrThrow(id); // Kiểm tra tồn tại trước khi xoá
        productRepository.deleteById(id);
        log.info("Product id: {} deleted successfully", id);
    }

    /**
     * Helper: tìm product theo ID, ném NotFoundException nếu không tồn tại.
     * Dùng chung cho get, update, delete để tránh lặp code.
     */
    private Product findProductOrThrow(Long id) {
        return productRepository.findById(id)
                .orElseThrow(() -> new NotFoundException("Product not found with id: " + id));
    }
}
