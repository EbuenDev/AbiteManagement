package com.enterprise.auth.audit;

import com.enterprise.auth.entity.AuditLog;
import com.enterprise.auth.repository.AuditLogRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;
import java.util.UUID;

@Service
public class AuditService {

    private final AuditLogRepository auditLogRepository;
    private final ObjectMapper objectMapper;

    public AuditService(AuditLogRepository auditLogRepository, ObjectMapper objectMapper) {
        this.auditLogRepository = auditLogRepository;
        this.objectMapper = objectMapper;
    }

    @Transactional
    public void recordEvent(UUID userId, String eventType, String ipAddress, String userAgent, Object details) {
        String safeIp = (ipAddress != null && !ipAddress.isBlank()) ? ipAddress : "UNKNOWN";
        String safeAgent = (userAgent != null && userAgent.length() > 255) ? userAgent.substring(0, 255) : userAgent;

        String jsonDetails = "{}";
        if (details != null) {
            try {
                if (details instanceof String str) {
                    if (str.trim().startsWith("{") && str.trim().endsWith("}")) {
                        jsonDetails = str.trim();
                    } else {
                        jsonDetails = objectMapper.writeValueAsString(Map.of("message", str));
                    }
                } else {
                    jsonDetails = objectMapper.writeValueAsString(details);
                }
            } catch (Exception ex) {
                jsonDetails = "{\"error\":\"Serialization failed\"}";
            }
        }

        AuditLog log = new AuditLog(userId, eventType, safeIp, safeAgent, jsonDetails);
        auditLogRepository.save(log);
    }

    public static String extractClientIp(HttpServletRequest request) {
        if (request == null) return "INTERNAL";
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader != null && !xfHeader.isBlank()) {
            return xfHeader.split(",")[0].trim();
        }
        return request.getRemoteAddr() != null ? request.getRemoteAddr() : "UNKNOWN";
    }
}
