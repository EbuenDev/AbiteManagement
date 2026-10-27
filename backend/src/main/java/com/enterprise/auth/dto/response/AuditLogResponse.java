package com.enterprise.auth.dto.response;

import com.enterprise.auth.entity.AuditLog;

import java.time.Instant;
import java.util.UUID;

public record AuditLogResponse(
        Long id,
        UUID userId,
        String eventType,
        String ipAddress,
        String userAgent,
        String details,
        Instant createdAt
) {
    public static AuditLogResponse fromEntity(AuditLog log) {
        return new AuditLogResponse(
                log.getId(),
                log.getUserId(),
                log.getEventType(),
                log.getIpAddress(),
                log.getUserAgent(),
                log.getDetails(),
                log.getCreatedAt()
        );
    }
}
