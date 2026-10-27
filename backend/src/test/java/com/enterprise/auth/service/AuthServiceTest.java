package com.enterprise.auth.service;

import com.enterprise.auth.audit.AuditService;
import com.enterprise.auth.dto.request.LoginRequest;
import com.enterprise.auth.dto.response.LoginChallengeResponse;
import com.enterprise.auth.dto.response.PreLoginResponse;
import com.enterprise.auth.entity.*;
import com.enterprise.auth.exception.ApiException;
import com.enterprise.auth.exception.ErrorCode;
import com.enterprise.auth.repository.AuthChallengeRepository;
import com.enterprise.auth.repository.UserRepository;
import com.enterprise.auth.security.EphemeralChallengeService;
import com.enterprise.auth.security.RateLimiterService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private AuthChallengeRepository authChallengeRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private AuditService auditService;

    private EphemeralChallengeService ephemeralChallengeService;
    private RateLimiterService rateLimiterService;
    private AuthService authService;

    private User activeUser;
    private UserSecuritySettings securitySettings;

    @BeforeEach
    void setUp() {
        ephemeralChallengeService = new EphemeralChallengeService();
        rateLimiterService = new RateLimiterService();
        rateLimiterService.reset();

        authService = new AuthService(
                userRepository,
                authChallengeRepository,
                ephemeralChallengeService,
                rateLimiterService,
                passwordEncoder,
                auditService
        );

        activeUser = new User("testuser", "test@enterprise.local", "hashedPassword", "clientsalt12345", UserStatus.ACTIVE);
        securitySettings = new UserSecuritySettings(activeUser);
        activeUser.setSecuritySettings(securitySettings);
    }

    @Test
    @DisplayName("Pre-login with existing user returns real client salt and valid public key")
    void preLogin_withExistingUser_returnsAuthenticSalt() {
        when(userRepository.findByIdentifier("testuser")).thenReturn(Optional.of(activeUser));

        PreLoginResponse response = authService.preLogin("testuser", "127.0.0.1");

        assertNotNull(response);
        assertEquals("clientsalt12345", response.clientSalt());
        assertNotNull(response.serverNonce());
        assertNotNull(response.publicKey());
        assertTrue(response.timestamp() > 0);
    }

    @Test
    @DisplayName("Pre-login with non-existent user returns synthetic salt to defeat timing/existence enumeration")
    void preLogin_withUnknownUser_returnsSyntheticSalt() {
        when(userRepository.findByIdentifier("nonexistent")).thenReturn(Optional.empty());

        PreLoginResponse response = authService.preLogin("nonexistent", "127.0.0.1");

        assertNotNull(response);
        assertNotNull(response.clientSalt());
        assertNotEquals("clientsalt12345", response.clientSalt());
        assertNotNull(response.serverNonce());
        assertNotNull(response.publicKey());
    }

    @Test
    @DisplayName("Login with valid direct password issues MFA challenge and does NOT create session")
    void login_withValidDirectPassword_issuesMfaChallenge() {
        when(userRepository.findByIdentifier("testuser")).thenReturn(Optional.of(activeUser));
        when(passwordEncoder.matches("CorrectPassword123!", "hashedPassword")).thenReturn(true);

        LoginRequest request = new LoginRequest("testuser", null, null, "CorrectPassword123!", null);
        LoginChallengeResponse response = authService.login(request, "127.0.0.1", "TestAgent");

        assertNotNull(response);
        assertTrue(response.mfaRequired());
        assertNotNull(response.challengeToken());
        assertTrue(response.expiresAt().isAfter(Instant.now()));

        verify(authChallengeRepository, times(1)).save(any(AuthChallenge.class));
        verify(auditService, times(1)).recordEvent(
                eq(activeUser.getId()),
                eq("LOGIN_CREDENTIALS_VERIFIED"),
                eq("127.0.0.1"),
                eq("TestAgent"),
                anyString()
        );
    }

    @Test
    @DisplayName("Login with ephemeral clone key decrypts payload, verifies anti-replay, and issues challenge")
    void login_withValidEphemeralCloneKey_succeeds() {
        when(userRepository.findByIdentifier("testuser")).thenReturn(Optional.of(activeUser));
        when(passwordEncoder.matches("SecretPassword123!", "hashedPassword")).thenReturn(true);

        // 1. Simulate pre-login handshake
        PreLoginResponse preLogin = authService.preLogin("testuser", "127.0.0.1");

        // 2. Encrypt clone key using server's ephemeral public key with embedded nonce and timestamp
        long timestamp = System.currentTimeMillis();
        String payload = "SecretPassword123!:" + preLogin.serverNonce() + ":" + timestamp;
        String encryptedCloneKey = EphemeralChallengeService.encryptPayload(payload, preLogin.publicKey());

        // 3. Submit login request with ephemeral clone key
        LoginRequest request = new LoginRequest("testuser", preLogin.serverNonce(), encryptedCloneKey, null, timestamp);
        LoginChallengeResponse response = authService.login(request, "127.0.0.1", "TestAgent");

        assertNotNull(response);
        assertTrue(response.mfaRequired());
        assertNotNull(response.challengeToken());
    }

    @Test
    @DisplayName("Replaying the same server nonce and clone key is rejected by anti-replay defense")
    void login_withEphemeralCloneKey_replayingNonceFails() {
        when(userRepository.findByIdentifier("testuser")).thenReturn(Optional.of(activeUser));
        when(passwordEncoder.matches("SecretPassword123!", "hashedPassword")).thenReturn(true);

        PreLoginResponse preLogin = authService.preLogin("testuser", "127.0.0.1");
        long timestamp = System.currentTimeMillis();
        String payload = "SecretPassword123!:" + preLogin.serverNonce() + ":" + timestamp;
        String encryptedCloneKey = EphemeralChallengeService.encryptPayload(payload, preLogin.publicKey());

        LoginRequest request = new LoginRequest("testuser", preLogin.serverNonce(), encryptedCloneKey, null, timestamp);

        // First attempt consumes and burns the nonce
        authService.login(request, "127.0.0.1", "TestAgent");

        // Second attempt with identical nonce must fail
        ApiException exception = assertThrows(ApiException.class, () ->
                authService.login(request, "127.0.0.1", "TestAgent"));

        assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatus());
        assertEquals(ErrorCode.INVALID_CREDENTIALS, exception.getErrorCode());
    }

    @Test
    @DisplayName("Login with invalid password increments failed attempts and returns 401")
    void login_withInvalidPassword_incrementsCount() {
        when(userRepository.findByIdentifier("testuser")).thenReturn(Optional.of(activeUser));
        when(passwordEncoder.matches("WrongPassword", "hashedPassword")).thenReturn(false);

        LoginRequest request = new LoginRequest("testuser", null, null, "WrongPassword", null);

        ApiException exception = assertThrows(ApiException.class, () ->
                authService.login(request, "127.0.0.1", "TestAgent"));

        assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatus());
        assertEquals(ErrorCode.INVALID_CREDENTIALS, exception.getErrorCode());
        assertEquals(1, securitySettings.getFailedLoginCount());
        verify(userRepository, times(1)).save(activeUser);
    }

    @Test
    @DisplayName("5 consecutive failed attempts locks account for 15 minutes")
    void login_with5ConsecutiveFailures_locksAccount() {
        when(userRepository.findByIdentifier("testuser")).thenReturn(Optional.of(activeUser));
        when(passwordEncoder.matches("WrongPassword", "hashedPassword")).thenReturn(false);
        securitySettings.setFailedLoginCount(4); // 4 prior failures

        LoginRequest request = new LoginRequest("testuser", null, null, "WrongPassword", null);

        ApiException exception = assertThrows(ApiException.class, () ->
                authService.login(request, "127.0.0.1", "TestAgent"));

        assertEquals(HttpStatus.LOCKED, exception.getStatus());
        assertEquals(ErrorCode.ACCOUNT_LOCKED, exception.getErrorCode());
        assertEquals(5, securitySettings.getFailedLoginCount());
        assertEquals(UserStatus.LOCKED, activeUser.getStatus());
        assertNotNull(securitySettings.getLockedUntil());
        assertTrue(securitySettings.getLockedUntil().isAfter(Instant.now()));

        verify(auditService, times(1)).recordEvent(
                eq(activeUser.getId()),
                eq("ACCOUNT_LOCKED"),
                eq("127.0.0.1"),
                eq("TestAgent"),
                anyString()
        );
    }

    @Test
    @DisplayName("Login on currently locked account throws 423 LOCKED without evaluating password")
    void login_withLockedAccount_throws423() {
        activeUser.setStatus(UserStatus.LOCKED);
        securitySettings.setLockedUntil(Instant.now().plus(10, ChronoUnit.MINUTES));
        when(userRepository.findByIdentifier("testuser")).thenReturn(Optional.of(activeUser));

        LoginRequest request = new LoginRequest("testuser", null, null, "AnyPassword", null);

        ApiException exception = assertThrows(ApiException.class, () ->
                authService.login(request, "127.0.0.1", "TestAgent"));

        assertEquals(HttpStatus.LOCKED, exception.getStatus());
        assertEquals(ErrorCode.ACCOUNT_LOCKED, exception.getErrorCode());
        verify(passwordEncoder, never()).matches(anyString(), anyString());
    }

    @Test
    @DisplayName("Login on suspended account throws 403 FORBIDDEN")
    void login_withSuspendedAccount_throws403() {
        activeUser.setStatus(UserStatus.SUSPENDED);
        when(userRepository.findByIdentifier("testuser")).thenReturn(Optional.of(activeUser));

        LoginRequest request = new LoginRequest("testuser", null, null, "AnyPassword", null);

        ApiException exception = assertThrows(ApiException.class, () ->
                authService.login(request, "127.0.0.1", "TestAgent"));

        assertEquals(HttpStatus.FORBIDDEN, exception.getStatus());
        assertEquals(ErrorCode.ACCOUNT_INACTIVE, exception.getErrorCode());
    }

    @Test
    @DisplayName("Login with unknown username performs dummy check and returns 401")
    void login_withUnknownUser_returns401() {
        when(userRepository.findByIdentifier("unknown")).thenReturn(Optional.empty());

        LoginRequest request = new LoginRequest("unknown", null, null, "AnyPassword", null);

        ApiException exception = assertThrows(ApiException.class, () ->
                authService.login(request, "127.0.0.1", "TestAgent"));

        assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatus());
        assertEquals(ErrorCode.INVALID_CREDENTIALS, exception.getErrorCode());
        verify(passwordEncoder, times(1)).matches(eq("AnyPassword"), anyString());
    }

    @Test
    @DisplayName("Exceeding login rate limit throws 429 TOO_MANY_REQUESTS")
    void login_rateLimitExceeded_throws429() {
        LoginRequest request = new LoginRequest("ratelimituser", null, null, "AnyPassword", null);

        // Exhaust 5 tokens
        for (int i = 0; i < 5; i++) {
            rateLimiterService.allowLogin("10.0.0.1", "ratelimituser");
        }

        ApiException exception = assertThrows(ApiException.class, () ->
                authService.login(request, "10.0.0.1", "TestAgent"));

        assertEquals(HttpStatus.TOO_MANY_REQUESTS, exception.getStatus());
        assertEquals(ErrorCode.RATE_LIMIT_EXCEEDED, exception.getErrorCode());
    }
}
