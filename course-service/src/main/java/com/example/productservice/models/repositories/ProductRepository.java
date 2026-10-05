package com.example.productservice.models.repositories;

import com.example.productservice.models.entities.Product;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ProductRepository extends JpaRepository<Product, Long> {

    /** Tìm kiếm theo category với phân trang */
    Page<Product> findByCategory(String category, Pageable pageable);

    /** Tìm kiếm theo tên (không phân biệt hoa/thường) với phân trang */
    Page<Product> findByNameContainingIgnoreCase(String name, Pageable pageable);
}
