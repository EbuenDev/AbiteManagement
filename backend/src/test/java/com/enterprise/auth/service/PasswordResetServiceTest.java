package com.enterprise.auth.service;

import com.enterprise.auth.audit.AuditService;
import com.enterprise.auth.dto.request.PasswordResetConfirmRequest;
import com.enterprise.auth.dto.response.PasswordResetResponse;
import com.enterprise.auth.entity.*;
import com.enterprise.auth.exception.ApiException;
import com.enterprise.auth.exception.ErrorCode;
import com.enterprise.auth.repository.PasswordResetTokenRepository;
import com.enterprise.auth.repository.UserRepository;
import com.enterprise.auth.util.SecurityUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class PasswordResetServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordResetTokenRepository tokenRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private AuditService auditService;

    @InjectMocks
    private PasswordResetService passwordResetService;

    private User testUser;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(passwordResetService, "exposeDevResetToken", true);
        testUser = new User("medical_staff", "staff@enterprise.local", "oldHash", "salt123", UserStatus.ACTIVE);
    }

    @Test
    @DisplayName("Anti-enumeration: Request reset for non-existent user returns safe message without throwing")
    void requestReset_nonExistentUser_returnsSafeMessage() {
        when(userRepository.findByUsernameIgnoreCase("ghost_user")).thenReturn(Optional.empty());

        PasswordResetResponse response = passwordResetService.requestPasswordReset("ghost_user", "127.0.0.1", "Mozilla/5.0");

        assertNotNull(response);
        assertTrue(response.message().contains("If an active account matching"));
        assertNull(response.devResetToken());
        verify(tokenRepository, never()).save(any(PasswordResetToken.class));
    }

    @Test
    @DisplayName("Request reset for active user stores hashed token and returns token in dev mode")
    void requestReset_activeUser_createsHashedToken() {
        when(userRepository.findByUsernameIgnoreCase("medical_staff")).thenReturn(Optional.of(testUser));

        PasswordResetResponse response = passwordResetService.requestPasswordReset("medical_staff", "127.0.0.1", "Mozilla/5.0");

        assertNotNull(response);
        assertNotNull(response.devResetToken());
        verify(tokenRepository, times(1)).deleteByUserId(testUser.getId());
        verify(tokenRepository, times(1)).save(any(PasswordResetToken.class));
        verify(auditService, times(1)).recordEvent(eq(testUser.getId()), eq("PASSWORD_RESET_REQUESTED"), any(), any(), any());
    }

    @Test
    @DisplayName("Confirm reset with valid token updates password and marks token used")
    void confirmReset_validToken_success() {
        String rawToken = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
        String tokenHash = SecurityUtils.sha256(rawToken);
        Instant futureExpiry = Instant.now().plus(10, ChronoUnit.MINUTES);

        PasswordResetToken token = new PasswordResetToken(testUser, tokenHash, futureExpiry);
        when(tokenRepository.findByTokenHash(tokenHash)).thenReturn(Optional.of(token));
        when(passwordEncoder.encode("BrandNewPassword123!@#")).thenReturn("brandNewArgonHash");

        PasswordResetConfirmRequest request = new PasswordResetConfirmRequest(rawToken, "BrandNewPassword123!@#");

        assertDoesNotThrow(() ->
                passwordResetService.confirmPasswordReset(request, "127.0.0.1", "Mozilla/5.0")
        );

        assertTrue(token.isUsed());
        assertEquals("brandNewArgonHash", testUser.getPasswordHash());
        verify(userRepository, times(1)).save(testUser);
        verify(tokenRepository, times(1)).save(token);
        verify(auditService, times(1)).recordEvent(eq(testUser.getId()), eq("PASSWORD_RESET_COMPLETED"), any(), any(), any());
    }

    @Test
    @DisplayName("Confirm reset with expired token throws BAD_REQUEST")
    void confirmReset_expiredToken_throws() {
        String rawToken = "expired_raw_token";
        String tokenHash = SecurityUtils.sha256(rawToken);
        Instant pastExpiry = Instant.now().minus(5, ChronoUnit.MINUTES);

        PasswordResetToken token = new PasswordResetToken(testUser, tokenHash, pastExpiry);
        when(tokenRepository.findByTokenHash(tokenHash)).thenReturn(Optional.of(token));

        PasswordResetConfirmRequest request = new PasswordResetConfirmRequest(rawToken, "BrandNewPassword123!@#");

        ApiException ex = assertThrows(ApiException.class, () ->
                passwordResetService.confirmPasswordReset(request, "127.0.0.1", "Mozilla/5.0")
        );

        assertEquals(ErrorCode.INVALID_CREDENTIALS, ex.getErrorCode());
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("Confirm reset with already-used token throws BAD_REQUEST")
    void confirmReset_alreadyUsedToken_throws() {
        String rawToken = "already_used_token";
        String tokenHash = SecurityUtils.sha256(rawToken);
        Instant futureExpiry = Instant.now().plus(10, ChronoUnit.MINUTES);

        PasswordResetToken token = new PasswordResetToken(testUser, tokenHash, futureExpiry);
        token.setUsedAt(Instant.now().minus(1, ChronoUnit.MINUTES));
        when(tokenRepository.findByTokenHash(tokenHash)).thenReturn(Optional.of(token));

        PasswordResetConfirmRequest request = new PasswordResetConfirmRequest(rawToken, "BrandNewPassword123!@#");

        ApiException ex = assertThrows(ApiException.class, () ->
                passwordResetService.confirmPasswordReset(request, "127.0.0.1", "Mozilla/5.0")
        );

        assertEquals(ErrorCode.INVALID_CREDENTIALS, ex.getErrorCode());
        verify(userRepository, never()).save(any(User.class));
    }
}
