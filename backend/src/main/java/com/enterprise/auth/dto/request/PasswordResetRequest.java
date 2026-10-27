package com.enterprise.auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record PasswordResetRequest(
        @NotBlank(message = "Identifier (username or email) is required")
        @Size(max = 120, message = "Identifier cannot exceed 120 characters")
        String identifier
) {}
