package com.enterprise.auth.dto.request;

import jakarta.validation.constraints.NotBlank;

public record TotpVerifyRequest(
        @NotBlank(message = "Challenge token is required")
        String challengeToken,

        @NotBlank(message = "Verification code or recovery code is required")
        String code
) {}
