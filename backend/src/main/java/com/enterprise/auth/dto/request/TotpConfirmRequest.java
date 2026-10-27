package com.enterprise.auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import java.util.List;

public record TotpConfirmRequest(
        String challengeToken,

        @NotBlank(message = "TOTP secret is required")
        String secret,

        @NotBlank(message = "Verification code is required")
        @Pattern(regexp = "^\\d{6}$", message = "Verification code must be 6 digits")
        String code,

        @NotEmpty(message = "Recovery codes are required")
        List<String> recoveryCodes
) {}
