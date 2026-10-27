package com.enterprise.auth.dto.response;

public record PasswordResetResponse(
        String message,
        String devResetToken
) {
    public static PasswordResetResponse of(String message) {
        return new PasswordResetResponse(message, null);
    }

    public static PasswordResetResponse withDevToken(String message, String devToken) {
        return new PasswordResetResponse(message, devToken);
    }
}
