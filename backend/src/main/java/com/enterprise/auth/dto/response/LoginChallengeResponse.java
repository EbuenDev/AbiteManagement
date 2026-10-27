package com.enterprise.auth.dto.response;

import java.time.Instant;

public record LoginChallengeResponse(
        String challengeToken,
        boolean mfaRequired,
        Instant expiresAt
) {}
