package com.enterprise.auth.controller;

import com.enterprise.auth.audit.AuditService;
import com.enterprise.auth.dto.request.PasswordResetConfirmRequest;
import com.enterprise.auth.dto.request.PasswordResetRequest;
import com.enterprise.auth.dto.response.PasswordResetResponse;
import com.enterprise.auth.service.PasswordResetService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/auth/password-reset")
public class PasswordResetController {

    private final PasswordResetService passwordResetService;

    public PasswordResetController(PasswordResetService passwordResetService) {
        this.passwordResetService = passwordResetService;
    }

    @PostMapping("/request")
    public ResponseEntity<PasswordResetResponse> requestReset(
            @Valid @RequestBody PasswordResetRequest request,
            HttpServletRequest servletRequest
    ) {
        String ip = AuditService.extractClientIp(servletRequest);
        String agent = servletRequest.getHeader("User-Agent");

        PasswordResetResponse response = passwordResetService.requestPasswordReset(request.identifier(), ip, agent);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/confirm")
    public ResponseEntity<Map<String, String>> confirmReset(
            @Valid @RequestBody PasswordResetConfirmRequest request,
            HttpServletRequest servletRequest
    ) {
        String ip = AuditService.extractClientIp(servletRequest);
        String agent = servletRequest.getHeader("User-Agent");

        passwordResetService.confirmPasswordReset(request, ip, agent);
        return ResponseEntity.ok(Map.of("message", "Password has been successfully reset. Please log in with your new credentials."));
    }
}
