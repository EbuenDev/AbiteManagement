package com.enterprise.auth.dto.response;

import com.enterprise.auth.entity.User;
import com.enterprise.auth.entity.UserStatus;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

public record UserResponse(
    UUID id,
    String username,
    String email,
    UserStatus status,
    Set<String> roles,
    boolean totpEnabled,
    Instant createdAt,
    Instant updatedAt
) {
    public static UserResponse fromEntity(User user) {
        boolean totp = user.getSecuritySettings() != null && user.getSecuritySettings().isTotpEnabled();
        Set<String> roleCodes = user.getRoles().stream()
                .map(r -> r.getCode().name())
                .collect(Collectors.toSet());

        return new UserResponse(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getStatus(),
                roleCodes,
                totp,
                user.getCreatedAt(),
                user.getUpdatedAt()
        );
    }
}
