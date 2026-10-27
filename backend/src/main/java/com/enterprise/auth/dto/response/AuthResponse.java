package com.enterprise.auth.dto.response;

public record AuthResponse(
        UserResponse user,
        String message
) {}
