package com.enterprise.auth.controller;

import com.enterprise.auth.dto.request.LoginRequest;
import com.enterprise.auth.dto.request.TotpConfirmRequest;
import com.enterprise.auth.dto.request.TotpVerifyRequest;
import com.enterprise.auth.dto.response.AuthResponse;
import com.enterprise.auth.dto.response.LoginChallengeResponse;
import com.enterprise.auth.dto.response.PreLoginResponse;
import com.enterprise.auth.dto.response.TotpSetupResponse;
import com.enterprise.auth.dto.response.UserResponse;
import com.enterprise.auth.security.CustomUserDetails;
import com.enterprise.auth.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
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

    /**
     * Initializes TOTP enrollment.
     * Accessible via an intermediate challengeToken (new account login) or an active user session.
     */
    @PostMapping("/totp/setup")
    public ResponseEntity<TotpSetupResponse> setupTotp(
            @RequestParam(value = "challengeToken", required = false) String challengeToken,
            @AuthenticationPrincipal CustomUserDetails userDetails
    ) {
        TotpSetupResponse response = authService.setupTotp(
                challengeToken,
                userDetails != null ? userDetails.getUser() : null
        );
        return ResponseEntity.ok(response);
    }

    /**
     * Confirms TOTP setup by verifying the first 6-digit code.
     * Persists AES-256-GCM encrypted secret and backup codes.
     */
    @PostMapping("/totp/confirm")
    public ResponseEntity<AuthResponse> confirmTotp(
            @Valid @RequestBody TotpConfirmRequest confirmRequest,
            HttpServletRequest request
    ) {
        String ipAddress = extractClientIp(request);
        String userAgent = request.getHeader("User-Agent");
        AuthResponse response = authService.confirmTotp(confirmRequest, ipAddress, userAgent, request);
        return ResponseEntity.ok(response);
    }

    /**
     * Step 2 MFA Challenge Verification & Full Session Establishment.
     * Verifies 6-digit TOTP code or backup recovery code and creates a secure HTTP session.
     */
    @PostMapping("/totp/verify")
    public ResponseEntity<AuthResponse> verifyTotp(
            @Valid @RequestBody TotpVerifyRequest verifyRequest,
            HttpServletRequest request
    ) {
        String ipAddress = extractClientIp(request);
        String userAgent = request.getHeader("User-Agent");
        AuthResponse response = authService.verifyTotp(verifyRequest, ipAddress, userAgent, request);
        return ResponseEntity.ok(response);
    }

    /**
     * Current authenticated user profile endpoint.
     */
    @GetMapping("/me")
    public ResponseEntity<UserResponse> getCurrentUser(@AuthenticationPrincipal CustomUserDetails userDetails) {
        if (userDetails == null || userDetails.getUser() == null) {
            return ResponseEntity.status(401).build();
        }
        return ResponseEntity.ok(UserResponse.fromEntity(userDetails.getUser()));
    }

    /**
     * Terminates the active HTTP session, invalidates cookies, and clears security context.
     */
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest request, HttpServletResponse response) {
        String ipAddress = extractClientIp(request);
        String userAgent = request.getHeader("User-Agent");
        authService.logout(request, response, ipAddress, userAgent);
        return ResponseEntity.noContent().build();
    }

    private String extractClientIp(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null || xfHeader.isBlank()) {
            return request.getRemoteAddr() != null ? request.getRemoteAddr() : "127.0.0.1";
        }
        return xfHeader.split(",")[0].trim();
    }
}
