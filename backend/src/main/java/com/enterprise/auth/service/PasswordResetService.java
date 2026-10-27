package com.enterprise.auth.service;

import com.enterprise.auth.audit.AuditService;
import com.enterprise.auth.dto.request.PasswordResetConfirmRequest;
import com.enterprise.auth.dto.response.PasswordResetResponse;
import com.enterprise.auth.entity.PasswordResetToken;
import com.enterprise.auth.entity.User;
import com.enterprise.auth.entity.UserStatus;
import com.enterprise.auth.exception.ApiException;
import com.enterprise.auth.exception.ErrorCode;
import com.enterprise.auth.repository.PasswordResetTokenRepository;
import com.enterprise.auth.repository.UserRepository;
import com.enterprise.auth.util.SecurityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

@Service
public class PasswordResetService {

    private static final Logger log = LoggerFactory.getLogger(PasswordResetService.class);
    private static final int RESET_TOKEN_EXPIRY_MINUTES = 15;

    private final UserRepository userRepository;
    private final PasswordResetTokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuditService auditService;

    @Value("${app.security.expose-dev-reset-token:true}")
    private boolean exposeDevResetToken;

    public PasswordResetService(
            UserRepository userRepository,
            PasswordResetTokenRepository tokenRepository,
            PasswordEncoder passwordEncoder,
            AuditService auditService
    ) {
        this.userRepository = userRepository;
        this.tokenRepository = tokenRepository;
        this.passwordEncoder = passwordEncoder;
        this.auditService = auditService;
    }

    @Transactional
    public PasswordResetResponse requestPasswordReset(String identifier, String ipAddress, String userAgent) {
        String genericMessage = "If an active account matching the provided identifier exists, password reset instructions have been generated.";

        if (identifier == null || identifier.isBlank()) {
            return PasswordResetResponse.of(genericMessage);
        }

        String trimmed = identifier.trim();
        Optional<User> userOpt = trimmed.contains("@")
                ? userRepository.findByEmailIgnoreCase(trimmed)
                : userRepository.findByUsernameIgnoreCase(trimmed);

        if (userOpt.isEmpty() || userOpt.get().getStatus() != UserStatus.ACTIVE) {
            // Anti-enumeration: log internally but return the identical uniform message
            log.info("Password reset requested for non-existent or inactive identifier: {}", trimmed);
            return PasswordResetResponse.of(genericMessage);
        }

        User user = userOpt.get();

        // Remove any existing active reset tokens for this user
        tokenRepository.deleteByUserId(user.getId());

        // Generate high-entropy 256-bit random token
        String rawToken = SecurityUtils.generateSecureRandomHex(32);
        String tokenHash = SecurityUtils.sha256(rawToken);
        Instant expiresAt = Instant.now().plus(RESET_TOKEN_EXPIRY_MINUTES, ChronoUnit.MINUTES);

        PasswordResetToken resetToken = new PasswordResetToken(user, tokenHash, expiresAt);
        tokenRepository.save(resetToken);

        auditService.recordEvent(
                user.getId(),
                "PASSWORD_RESET_REQUESTED",
                ipAddress,
                userAgent,
                String.format("Password reset token generated for user '%s' (expires in %d minutes)",
                        user.getUsername(), RESET_TOKEN_EXPIRY_MINUTES)
        );

        log.info("Password reset token generated for user: {}", user.getUsername());

        if (exposeDevResetToken) {
            return PasswordResetResponse.withDevToken(genericMessage, rawToken);
        }
        return PasswordResetResponse.of(genericMessage);
    }

    @Transactional(noRollbackFor = ApiException.class)
    public void confirmPasswordReset(PasswordResetConfirmRequest request, String ipAddress, String userAgent) {
        String tokenHash = SecurityUtils.sha256(request.token().trim());

        PasswordResetToken resetToken = tokenRepository.findByTokenHash(tokenHash)
                .orElseThrow(() -> new ApiException(HttpStatus.BAD_REQUEST, ErrorCode.INVALID_CREDENTIALS,
                        "Invalid or expired password reset token"));

        if (resetToken.isUsed() || resetToken.isExpired()) {
            throw new ApiException(HttpStatus.BAD_REQUEST, ErrorCode.INVALID_CREDENTIALS,
                    "Invalid or expired password reset token");
        }

        User user = resetToken.getUser();
        if (user.getStatus() != UserStatus.ACTIVE) {
            throw new ApiException(HttpStatus.FORBIDDEN, ErrorCode.ACCOUNT_INACTIVE,
                    "Account is currently suspended or inactive");
        }

        // Apply new password with Argon2id
        user.setPasswordHash(passwordEncoder.encode(request.newPassword()));

        // Rotate client salt to invalidate all previous client proofs
        user.setClientSalt(SecurityUtils.generateSecureRandomHex(32));

        // Reset account lockout counters
        user.resetFailedAttempts();

        // Invalidate token
        resetToken.setUsedAt(Instant.now());

        userRepository.save(user);
        tokenRepository.save(resetToken);

        auditService.recordEvent(
                user.getId(),
                "PASSWORD_RESET_COMPLETED",
                ipAddress,
                userAgent,
                String.format("Password successfully reset via token for user '%s'", user.getUsername())
        );
    }
}
