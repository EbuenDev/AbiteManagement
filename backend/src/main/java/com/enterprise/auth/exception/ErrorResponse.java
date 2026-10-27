package com.enterprise.auth.exception;

import java.time.Instant;
import java.util.Map;

public record ErrorResponse(
    Instant timestamp,
    int status,
    ErrorCode errorCode,
    String message,
    String correlationId,
    Map<String, String> validationErrors
) {
    public ErrorResponse(int status, ErrorCode errorCode, String message, String correlationId) {
        this(Instant.now(), status, errorCode, message, correlationId, null);
    }

    public ErrorResponse(int status, ErrorCode errorCode, String message, String correlationId, Map<String, String> validationErrors) {
        this(Instant.now(), status, errorCode, message, correlationId, validationErrors);
    }
}
