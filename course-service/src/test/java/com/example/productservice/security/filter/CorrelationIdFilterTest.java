package com.example.productservice.security.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

class CorrelationIdFilterTest {

    private final CorrelationIdFilter filter = new CorrelationIdFilter();

    @Test
    @DisplayName("should propagate valid X-Correlation-Id header")
    void shouldPropagateExistingCorrelationId() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(CorrelationIdFilter.CORRELATION_ID_HEADER, "cid-valid-1234");
        MockHttpServletResponse response = new MockHttpServletResponse();

        FilterChain filterChain = (req, res) -> {
            assertEquals("cid-valid-1234", MDC.get(CorrelationIdFilter.CORRELATION_ID_MDC_KEY));
        };

        filter.doFilterInternal(request, response, filterChain);

        assertEquals("cid-valid-1234", response.getHeader(CorrelationIdFilter.CORRELATION_ID_HEADER));
        assertNull(MDC.get(CorrelationIdFilter.CORRELATION_ID_MDC_KEY));
    }

    @Test
    @DisplayName("should generate new UUID when correlation ID header is missing")
    void shouldGenerateNewCorrelationIdWhenMissing() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        FilterChain filterChain = (req, res) -> {
            String mdcId = MDC.get(CorrelationIdFilter.CORRELATION_ID_MDC_KEY);
            assertNotNull(mdcId);
            assertTrue(mdcId.matches("^[0-9a-fA-F-]{36}$"));
        };

        filter.doFilterInternal(request, response, filterChain);

        String responseHeader = response.getHeader(CorrelationIdFilter.CORRELATION_ID_HEADER);
        assertNotNull(responseHeader);
        assertTrue(responseHeader.matches("^[0-9a-fA-F-]{36}$"));
        assertNull(MDC.get(CorrelationIdFilter.CORRELATION_ID_MDC_KEY));
    }

    @Test
    @DisplayName("should sanitize malicious/invalid correlation ID with new UUID")
    void shouldSanitizeMaliciousCorrelationId() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(CorrelationIdFilter.CORRELATION_ID_HEADER, "invalid\r\nCRLF-injection$$$");
        MockHttpServletResponse response = new MockHttpServletResponse();

        FilterChain filterChain = (req, res) -> {
            String mdcId = MDC.get(CorrelationIdFilter.CORRELATION_ID_MDC_KEY);
            assertNotNull(mdcId);
            assertFalse(mdcId.contains("\r"));
            assertFalse(mdcId.contains("\n"));
            assertTrue(mdcId.matches("^[0-9a-fA-F-]{36}$"));
        };

        filter.doFilterInternal(request, response, filterChain);

        String responseHeader = response.getHeader(CorrelationIdFilter.CORRELATION_ID_HEADER);
        assertNotNull(responseHeader);
        assertTrue(responseHeader.matches("^[0-9a-fA-F-]{36}$"));
    }
}
