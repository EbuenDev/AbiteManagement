package com.enterprise.auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record LoginRequest(
        @NotBlank(message = "Username or email identifier is required")
        @Size(max = 255, message = "Identifier must not exceed 255 characters")
        String identifier,

        @Size(max = 128, message = "Server nonce format is invalid")
        String serverNonce,

        String cloneKey,

        @Size(max = 255, message = "Password must not exceed 255 characters")
        String password,

        Long timestamp
) {}
