package com.enterprise.auth.service;

import com.enterprise.auth.audit.AuditService;
import com.enterprise.auth.dto.request.LoginRequest;
import com.enterprise.auth.dto.request.TotpConfirmRequest;
import com.enterprise.auth.dto.request.TotpVerifyRequest;
import com.enterprise.auth.dto.response.AuthResponse;
import com.enterprise.auth.dto.response.LoginChallengeResponse;
import com.enterprise.auth.dto.response.PreLoginResponse;
import com.enterprise.auth.dto.response.TotpSetupResponse;
import com.enterprise.auth.entity.*;
import com.enterprise.auth.exception.ApiException;
import com.enterprise.auth.exception.ErrorCode;
import com.enterprise.auth.repository.AuthChallengeRepository;
import com.enterprise.auth.repository.RecoveryCodeRepository;
import com.enterprise.auth.repository.UserRepository;
import com.enterprise.auth.repository.UserSecuritySettingsRepository;
import com.enterprise.auth.security.AesGcmEncryptionService;
import com.enterprise.auth.security.EphemeralChallengeService;
import com.enterprise.auth.security.RateLimiterService;
import com.enterprise.auth.security.TotpService;
import com.enterprise.auth.util.SecurityUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;

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
    private UserSecuritySettingsRepository userSecuritySettingsRepository;

    @Mock
    private RecoveryCodeRepository recoveryCodeRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private AuditService auditService;

    @Mock
    private TotpService totpService;

    private EphemeralChallengeService ephemeralChallengeService;
    private RateLimiterService rateLimiterService;
    private AesGcmEncryptionService aesGcmEncryptionService;
    private AuthService authService;

    private User activeUser;
    private UserSecuritySettings securitySettings;

    @BeforeEach
    void setUp() {
        ephemeralChallengeService = new EphemeralChallengeService();
        rateLimiterService = new RateLimiterService();
        rateLimiterService.reset();

        // 32-byte hex key for tests
        aesGcmEncryptionService = new AesGcmEncryptionService("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

        authService = new AuthService(
                userRepository,
                authChallengeRepository,
                userSecuritySettingsRepository,
                recoveryCodeRepository,
                ephemeralChallengeService,
                rateLimiterService,
                totpService,
                aesGcmEncryptionService,
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
        assertFalse(response.totpEnrolled());
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

        PreLoginResponse preLogin = authService.preLogin("testuser", "127.0.0.1");

        long timestamp = System.currentTimeMillis();
        String payload = "SecretPassword123!:" + preLogin.serverNonce() + ":" + timestamp;
        String encryptedCloneKey = EphemeralChallengeService.encryptPayload(payload, preLogin.publicKey());

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

        authService.login(request, "127.0.0.1", "TestAgent");

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
        securitySettings.setFailedLoginCount(4);

        LoginRequest request = new LoginRequest("testuser", null, null, "WrongPassword", null);

        ApiException exception = assertThrows(ApiException.class, () ->
                authService.login(request, "127.0.0.1", "TestAgent"));

        assertEquals(HttpStatus.LOCKED, exception.getStatus());
        assertEquals(ErrorCode.ACCOUNT_LOCKED, exception.getErrorCode());
        assertEquals(5, securitySettings.getFailedLoginCount());
        assertEquals(UserStatus.LOCKED, activeUser.getStatus());
        assertNotNull(securitySettings.getLockedUntil());
        assertTrue(securitySettings.getLockedUntil().isAfter(Instant.now()));
    }

    @Test
    @DisplayName("Setup TOTP with pending challenge token returns secret, QR code URI, and recovery codes")
    void setupTotp_withPendingChallenge_returnsSetupDetails() {
        String token = "my-test-token-123";
        String tokenHash = SecurityUtils.sha256(token);
        AuthChallenge challenge = new AuthChallenge(activeUser, tokenHash, AuthChallengeStatus.PENDING, Instant.now().plus(300, ChronoUnit.SECONDS));

        when(authChallengeRepository.findByTokenHashAndStatus(tokenHash, AuthChallengeStatus.PENDING))
                .thenReturn(Optional.of(challenge));
        when(totpService.generateSecret()).thenReturn("JBSWY3DPEHPK3PXP");
        when(totpService.generateQrCodeDataUri("testuser", "JBSWY3DPEHPK3PXP")).thenReturn("data:image/png;base64,mockQrCode");
        when(totpService.generateRecoveryCodes()).thenReturn(List.of("AAAA-BBBB", "CCCC-DDDD"));

        TotpSetupResponse response = authService.setupTotp(token, null);

        assertNotNull(response);
        assertEquals("JBSWY3DPEHPK3PXP", response.manualKey());
        assertEquals("data:image/png;base64,mockQrCode", response.qrCodeDataUri());
        assertEquals(2, response.recoveryCodes().size());
    }

    @Test
    @DisplayName("Confirm TOTP with valid code encrypts secret, hashes recovery codes, and completes challenge")
    void confirmTotp_withValidCode_encryptsAndEstablishesSession() {
        String token = "confirm-token-123";
        String tokenHash = SecurityUtils.sha256(token);
        AuthChallenge challenge = new AuthChallenge(activeUser, tokenHash, AuthChallengeStatus.PENDING, Instant.now().plus(300, ChronoUnit.SECONDS));

        when(authChallengeRepository.findByTokenHashAndStatus(tokenHash, AuthChallengeStatus.PENDING))
                .thenReturn(Optional.of(challenge));
        when(totpService.verifyCode("JBSWY3DPEHPK3PXP", "123456", 0L))
                .thenReturn(new TotpService.TotpVerificationResult(true, 12345L, null));
        when(passwordEncoder.encode(anyString())).thenReturn("hashed-code");

        TotpConfirmRequest request = new TotpConfirmRequest(token, "JBSWY3DPEHPK3PXP", "123456", List.of("CODE-1111", "CODE-2222"));
        MockHttpServletRequest httpRequest = new MockHttpServletRequest();

        AuthResponse response = authService.confirmTotp(request, "127.0.0.1", "TestAgent", httpRequest);

        assertNotNull(response);
        assertEquals("testuser", response.user().username());
        assertTrue(securitySettings.isTotpEnabled());
        assertNotNull(securitySettings.getEncryptedTotpSecret());
        assertNotNull(securitySettings.getTotpEncryptionIv());

        verify(recoveryCodeRepository, times(2)).save(any(RecoveryCode.class));
        verify(authChallengeRepository, atLeastOnce()).save(challenge);
        assertEquals(AuthChallengeStatus.COMPLETED, challenge.getStatus());
    }

    @Test
    @DisplayName("Verify TOTP with valid 6-digit code marks challenge COMPLETED and creates session")
    void verifyTotp_withValidTotpCode_succeeds() {
        String token = "verify-token-123";
        String tokenHash = SecurityUtils.sha256(token);

        // Setup user with enrolled TOTP secret
        AesGcmEncryptionService.EncryptedPayload encrypted = aesGcmEncryptionService.encrypt("BASE32SECRET");
        securitySettings.setTotpEnabled(true);
        securitySettings.setEncryptedTotpSecret(encrypted.base64Ciphertext());
        securitySettings.setTotpEncryptionIv(encrypted.base64Iv());

        AuthChallenge challenge = new AuthChallenge(activeUser, tokenHash, AuthChallengeStatus.PENDING, Instant.now().plus(300, ChronoUnit.SECONDS));
        when(authChallengeRepository.findByTokenHash(tokenHash)).thenReturn(Optional.of(challenge));
        when(totpService.verifyCode("BASE32SECRET", "654321", 0L))
                .thenReturn(new TotpService.TotpVerificationResult(true, 99999L, null));

        TotpVerifyRequest request = new TotpVerifyRequest(token, "654321");
        MockHttpServletRequest httpRequest = new MockHttpServletRequest();

        AuthResponse response = authService.verifyTotp(request, "127.0.0.1", "TestAgent", httpRequest);

        assertNotNull(response);
        assertEquals("testuser", response.user().username());
        assertEquals(AuthChallengeStatus.COMPLETED, challenge.getStatus());
        verify(authChallengeRepository, times(1)).save(challenge);
    }

    @Test
    @DisplayName("Verify TOTP with valid backup recovery code succeeds and marks code as used")
    void verifyTotp_withValidRecoveryCode_succeeds() {
        String token = "recovery-token-123";
        String tokenHash = SecurityUtils.sha256(token);

        AesGcmEncryptionService.EncryptedPayload encrypted = aesGcmEncryptionService.encrypt("BASE32SECRET");
        securitySettings.setTotpEnabled(true);
        securitySettings.setEncryptedTotpSecret(encrypted.base64Ciphertext());
        securitySettings.setTotpEncryptionIv(encrypted.base64Iv());

        AuthChallenge challenge = new AuthChallenge(activeUser, tokenHash, AuthChallengeStatus.PENDING, Instant.now().plus(300, ChronoUnit.SECONDS));
        when(authChallengeRepository.findByTokenHash(tokenHash)).thenReturn(Optional.of(challenge));

        // Code is not a 6-digit numeric TOTP code, but an alphanumeric recovery code "ABCD-1234"
        RecoveryCode activeRecoveryCode = new RecoveryCode(activeUser, "hashed-recovery-code");
        when(recoveryCodeRepository.findActiveCodesByUserId(activeUser.getId()))
                .thenReturn(List.of(activeRecoveryCode));
        when(passwordEncoder.matches("ABCD-1234", "hashed-recovery-code")).thenReturn(true);

        TotpVerifyRequest request = new TotpVerifyRequest(token, "ABCD-1234");
        MockHttpServletRequest httpRequest = new MockHttpServletRequest();

        AuthResponse response = authService.verifyTotp(request, "127.0.0.1", "TestAgent", httpRequest);

        assertNotNull(response);
        assertTrue(activeRecoveryCode.isUsed());
        assertEquals(AuthChallengeStatus.COMPLETED, challenge.getStatus());
        verify(recoveryCodeRepository, times(1)).save(activeRecoveryCode);
    }

    @Test
    @DisplayName("Verify TOTP with 3 invalid attempts locks the challenge to FAILED")
    void verifyTotp_with3InvalidAttempts_locksChallenge() {
        String token = "failed-challenge-token";
        String tokenHash = SecurityUtils.sha256(token);

        AesGcmEncryptionService.EncryptedPayload encrypted = aesGcmEncryptionService.encrypt("BASE32SECRET");
        securitySettings.setTotpEnabled(true);
        securitySettings.setEncryptedTotpSecret(encrypted.base64Ciphertext());
        securitySettings.setTotpEncryptionIv(encrypted.base64Iv());

        AuthChallenge challenge = new AuthChallenge(activeUser, tokenHash, AuthChallengeStatus.PENDING, Instant.now().plus(300, ChronoUnit.SECONDS));
        challenge.setFailedAttempts(2); // 2 prior failures

        when(authChallengeRepository.findByTokenHash(tokenHash)).thenReturn(Optional.of(challenge));
        when(totpService.verifyCode("BASE32SECRET", "000000", 0L))
                .thenReturn(new TotpService.TotpVerificationResult(false, 0L, "Invalid code"));
        when(recoveryCodeRepository.findActiveCodesByUserId(activeUser.getId())).thenReturn(List.of());

        TotpVerifyRequest request = new TotpVerifyRequest(token, "000000");
        MockHttpServletRequest httpRequest = new MockHttpServletRequest();

        ApiException exception = assertThrows(ApiException.class, () ->
                authService.verifyTotp(request, "127.0.0.1", "TestAgent", httpRequest));

        assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatus());
        assertEquals(ErrorCode.INVALID_TOTP_CODE, exception.getErrorCode());
        assertEquals(3, challenge.getFailedAttempts());
        assertEquals(AuthChallengeStatus.FAILED, challenge.getStatus());
        verify(authChallengeRepository, times(1)).save(challenge);
    }

    @Test
    @DisplayName("Logout clears SecurityContext, invalidates session, and clears JSESSIONID cookie")
    void logout_invalidatesSessionAndClearsContext() {
        MockHttpServletRequest httpRequest = new MockHttpServletRequest();
        httpRequest.getSession(true); // create active session
        MockHttpServletResponse httpResponse = new MockHttpServletResponse();

        authService.logout(httpRequest, httpResponse, "127.0.0.1", "TestAgent");

        assertNull(httpRequest.getSession(false));
        assertNotNull(httpResponse.getHeader("Set-Cookie"));
        assertTrue(httpResponse.getHeader("Set-Cookie").contains("JSESSIONID="));
        assertTrue(httpResponse.getHeader("Set-Cookie").contains("Max-Age=0"));
    }
}
