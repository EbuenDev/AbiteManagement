package com.enterprise.auth.dto.response;

public record PreLoginResponse(
        String serverNonce,
        String clientSalt,
        String publicKey,
        long timestamp
) {}
