package com.enterprise.auth.controller;

import com.enterprise.auth.dto.request.LoginRequest;
import com.enterprise.auth.dto.response.LoginChallengeResponse;
import com.enterprise.auth.dto.response.PreLoginResponse;
import com.enterprise.auth.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    /**
     * Pre-login handshake endpoint.
     * Issues an ephemeral server nonce and client salt for client-side clone key derivation.
     */
    @GetMapping("/pre-login")
    public ResponseEntity<PreLoginResponse> preLogin(
            @RequestParam("identifier") String identifier,
            HttpServletRequest request
    ) {
        String ipAddress = extractClientIp(request);
        PreLoginResponse response = authService.preLogin(identifier, ipAddress);
        return ResponseEntity.ok(response);
    }

    /**
     * Step 1 Primary Authentication endpoint.
     * Verifies either the ephemeral clone key or password and issues a short-lived MFA challenge token.
     */
    @PostMapping("/login")
    public ResponseEntity<LoginChallengeResponse> login(
            @Valid @RequestBody LoginRequest loginRequest,
            HttpServletRequest request
    ) {
        String ipAddress = extractClientIp(request);
        String userAgent = request.getHeader("User-Agent");
        LoginChallengeResponse response = authService.login(loginRequest, ipAddress, userAgent);
        return ResponseEntity.ok(response);
    }

    private String extractClientIp(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null || xfHeader.isBlank()) {
            return request.getRemoteAddr() != null ? request.getRemoteAddr() : "127.0.0.1";
        }
        return xfHeader.split(",")[0].trim();
    }
}
