package com.enterprise.auth.dto.response;

import java.util.List;

public record TotpSetupResponse(
        String manualKey,
        String qrCodeDataUri,
        List<String> recoveryCodes
) {}
