package com.enterprise.auth.service;

import com.enterprise.auth.audit.AuditService;
import com.enterprise.auth.dto.request.LoginRequest;
import com.enterprise.auth.dto.request.TotpConfirmRequest;
import com.enterprise.auth.dto.request.TotpVerifyRequest;
import com.enterprise.auth.dto.response.AuthResponse;
import com.enterprise.auth.dto.response.LoginChallengeResponse;
import com.enterprise.auth.dto.response.PreLoginResponse;
import com.enterprise.auth.dto.response.TotpSetupResponse;
import com.enterprise.auth.dto.response.UserResponse;
import com.enterprise.auth.entity.*;
import com.enterprise.auth.exception.ApiException;
import com.enterprise.auth.exception.ErrorCode;
import com.enterprise.auth.repository.AuthChallengeRepository;
import com.enterprise.auth.repository.RecoveryCodeRepository;
import com.enterprise.auth.repository.UserRepository;
import com.enterprise.auth.repository.UserSecuritySettingsRepository;
import com.enterprise.auth.security.*;
import com.enterprise.auth.util.SecurityUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;

@Service
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);
    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final int MAX_CHALLENGE_ATTEMPTS = 3;
    private static final int LOCKOUT_DURATION_MINUTES = 15;
    private static final int CHALLENGE_TTL_SECONDS = 300; // 5 minutes

    // Dummy Argon2 hash to simulate verification timing when user does not exist
    private static final String DUMMY_HASH = "$argon2id$v=19$m=65536,t=3,p=1$c29tZXNhbHQxMjM0NTY3OA$qM0jLp4o5m1s8f4v6x2y0z1a3b5c7d9e";

    private final UserRepository userRepository;
    private final AuthChallengeRepository authChallengeRepository;
    private final UserSecuritySettingsRepository userSecuritySettingsRepository;
    private final RecoveryCodeRepository recoveryCodeRepository;
    private final EphemeralChallengeService ephemeralChallengeService;
    private final RateLimiterService rateLimiterService;
    private final TotpService totpService;
    private final AesGcmEncryptionService aesGcmEncryptionService;
    private final PasswordEncoder passwordEncoder;
    private final AuditService auditService;

    public AuthService(
            UserRepository userRepository,
            AuthChallengeRepository authChallengeRepository,
            UserSecuritySettingsRepository userSecuritySettingsRepository,
            RecoveryCodeRepository recoveryCodeRepository,
            EphemeralChallengeService ephemeralChallengeService,
            RateLimiterService rateLimiterService,
            TotpService totpService,
            AesGcmEncryptionService aesGcmEncryptionService,
            PasswordEncoder passwordEncoder,
            AuditService auditService
    ) {
        this.userRepository = userRepository;
        this.authChallengeRepository = authChallengeRepository;
        this.userSecuritySettingsRepository = userSecuritySettingsRepository;
        this.recoveryCodeRepository = recoveryCodeRepository;
        this.ephemeralChallengeService = ephemeralChallengeService;
        this.rateLimiterService = rateLimiterService;
        this.totpService = totpService;
        this.aesGcmEncryptionService = aesGcmEncryptionService;
        this.passwordEncoder = passwordEncoder;
        this.auditService = auditService;
    }

    /**
     * Step 0: Generates pre-login challenge and ephemeral session key.
     * Prevents user enumeration by producing consistent responses with synthetic salt for non-existent users.
     */
    public PreLoginResponse preLogin(String identifier, String ipAddress) {
        if (!rateLimiterService.allowPreLogin(ipAddress)) {
            throw new ApiException(HttpStatus.TOO_MANY_REQUESTS, ErrorCode.RATE_LIMIT_EXCEEDED,
                    "Pre-login request rate limit exceeded. Please wait a moment before trying again.");
        }

        if (identifier == null || identifier.isBlank()) {
            throw new ApiException(HttpStatus.BAD_REQUEST, ErrorCode.VALIDATION_FAILED,
                    "Identifier (username or email) is required");
        }

        Optional<User> userOpt = userRepository.findByIdentifier(identifier.trim());

        // Use authentic salt if user exists, otherwise generate synthetic deterministic salt to defeat enumeration
        String clientSalt = userOpt.map(User::getClientSalt)
                .orElseGet(() -> SecurityUtils.sha256(identifier.trim().toLowerCase() + "-synthetic-salt").substring(0, 32));

        EphemeralChallengeService.ChallengeDescriptor descriptor = ephemeralChallengeService.generateChallenge(clientSalt);

        return new PreLoginResponse(
                descriptor.serverNonce(),
                descriptor.clientSalt(),
                descriptor.publicKey(),
                descriptor.timestamp()
        );
    }

    /**
     * Step 1: Primary Credential Verification (Password / Ephemeral Clone Key).
     * Strictly verifies identity and issues a short-lived intermediate AuthChallenge token.
     * Does NOT create an authenticated HTTP session or Spring Security context.
     */
    @Transactional(noRollbackFor = ApiException.class)
    public LoginChallengeResponse login(LoginRequest request, String ipAddress, String userAgent) {
        String identifier = request.identifier().trim();

        // 1. Enforce rate limiting
        if (!rateLimiterService.allowLogin(ipAddress, identifier)) {
            auditService.recordEvent(
                    null,
                    "LOGIN_RATE_LIMITED",
                    ipAddress,
                    userAgent,
                    "Exceeded login rate limit for identifier: " + identifier
            );
            throw new ApiException(HttpStatus.TOO_MANY_REQUESTS, ErrorCode.RATE_LIMIT_EXCEEDED,
                    "Too many failed login attempts. Please wait a few minutes before retrying.");
        }

        // 2. Resolve password (either decrypted from ephemeral cloneKey or supplied directly)
        String rawPassword;
        if (request.cloneKey() != null && !request.cloneKey().isBlank()) {
            rawPassword = ephemeralChallengeService.consumeAndDecrypt(request.serverNonce(), request.cloneKey());
        } else if (request.password() != null && !request.password().isBlank()) {
            rawPassword = request.password();
        } else {
            throw new ApiException(HttpStatus.BAD_REQUEST, ErrorCode.VALIDATION_FAILED,
                    "Authentication requires either an ephemeral clone key or password");
        }

        // 3. User lookup
        Optional<User> userOpt = userRepository.findByIdentifier(identifier);
        if (userOpt.isEmpty()) {
            // Mitigate timing oracle attacks with dummy verification
            passwordEncoder.matches(rawPassword, DUMMY_HASH);
            auditService.recordEvent(
                    null,
                    "LOGIN_FAILED_UNKNOWN_USER",
                    ipAddress,
                    userAgent,
                    "Authentication failed for non-existent identifier: " + identifier
            );
            throw new ApiException(HttpStatus.UNAUTHORIZED, ErrorCode.INVALID_CREDENTIALS,
                    "Invalid username or password");
        }

        User user = userOpt.get();
        UserSecuritySettings settings = user.getSecuritySettings();
        if (settings == null) {
            settings = new UserSecuritySettings(user);
            user.setSecuritySettings(settings);
        }

        // 4. Account status and lockout evaluation
        if (user.getStatus() == UserStatus.LOCKED) {
            Instant lockedUntil = settings.getLockedUntil();
            if (lockedUntil != null && lockedUntil.isAfter(Instant.now())) {
                auditService.recordEvent(
                        user.getId(),
                        "LOGIN_ATTEMPT_LOCKED_ACCOUNT",
                        ipAddress,
                        userAgent,
                        "Attempted login on account locked until: " + lockedUntil
                );
                throw new ApiException(HttpStatus.LOCKED, ErrorCode.ACCOUNT_LOCKED,
                        "Your account is temporarily locked due to consecutive failed login attempts. Please try again later.");
            } else {
                // Auto-unlock after lockout period has elapsed
                log.info("Auto-unlocking account for user '{}' as lockout period expired", user.getUsername());
                settings.setFailedLoginCount(0);
                settings.setLockedUntil(null);
                user.setStatus(UserStatus.ACTIVE);
            }
        }

        if (user.getStatus() == UserStatus.SUSPENDED || user.getStatus() == UserStatus.DEACTIVATED) {
            auditService.recordEvent(
                    user.getId(),
                    "LOGIN_ATTEMPT_INACTIVE_ACCOUNT",
                    ipAddress,
                    userAgent,
                    "Attempted login on inactive account with status: " + user.getStatus()
            );
            throw new ApiException(HttpStatus.FORBIDDEN, ErrorCode.ACCOUNT_INACTIVE,
                    "This account has been deactivated or suspended. Please contact an administrator.");
        }

        // 5. Password verification (Argon2id)
        boolean passwordMatches = passwordEncoder.matches(rawPassword, user.getPasswordHash());
        if (!passwordMatches) {
            int newFailedCount = settings.getFailedLoginCount() + 1;
            settings.setFailedLoginCount(newFailedCount);

            if (newFailedCount >= MAX_FAILED_ATTEMPTS) {
                Instant lockUntil = Instant.now().plus(LOCKOUT_DURATION_MINUTES, ChronoUnit.MINUTES);
                settings.setLockedUntil(lockUntil);
                user.setStatus(UserStatus.LOCKED);
                userRepository.save(user);

                auditService.recordEvent(
                        user.getId(),
                        "ACCOUNT_LOCKED",
                        ipAddress,
                        userAgent,
                        String.format("Account locked for %d minutes after %d consecutive failed attempts",
                                LOCKOUT_DURATION_MINUTES, newFailedCount)
                );

                throw new ApiException(HttpStatus.LOCKED, ErrorCode.ACCOUNT_LOCKED,
                        "Account locked for 15 minutes due to multiple failed login attempts.");
            } else {
                userRepository.save(user);
                auditService.recordEvent(
                        user.getId(),
                        "LOGIN_FAILED",
                        ipAddress,
                        userAgent,
                        String.format("Invalid password attempt %d of %d", newFailedCount, MAX_FAILED_ATTEMPTS)
                );

                throw new ApiException(HttpStatus.UNAUTHORIZED, ErrorCode.INVALID_CREDENTIALS,
                        "Invalid username or password");
            }
        }

        // 6. Successful credential verification: reset failed counters
        settings.setFailedLoginCount(0);
        settings.setLockedUntil(null);
        userRepository.save(user);

        // 7. Generate intermediate MFA challenge
        String rawChallengeToken = SecurityUtils.generateSecureRandomHex(32);
        String tokenHash = SecurityUtils.sha256(rawChallengeToken);
        Instant challengeExpiry = Instant.now().plus(CHALLENGE_TTL_SECONDS, ChronoUnit.SECONDS);

        AuthChallenge challenge = new AuthChallenge(user, tokenHash, AuthChallengeStatus.PENDING, challengeExpiry);
        authChallengeRepository.save(challenge);

        auditService.recordEvent(
                user.getId(),
                "LOGIN_CREDENTIALS_VERIFIED",
                ipAddress,
                userAgent,
                "Primary credentials verified successfully. Intermediate MFA challenge issued."
        );

        boolean isTotpEnrolled = settings.isTotpEnabled() && settings.getEncryptedTotpSecret() != null;

        // Explicitly return pending MFA status; no session or security context created
        return new LoginChallengeResponse(rawChallengeToken, true, isTotpEnrolled, challengeExpiry);
    }

    /**
     * Generates a new TOTP secret, QR code, and backup recovery codes.
     * Accessible either via an intermediate challengeToken (first-time login) or an authenticated user.
     */
    @Transactional(readOnly = true)
    public TotpSetupResponse setupTotp(String challengeToken, User principal) {
        User targetUser = resolveTargetUser(challengeToken, principal);

        String secret = totpService.generateSecret();
        String qrCodeDataUri = totpService.generateQrCodeDataUri(targetUser.getUsername(), secret);
        List<String> recoveryCodes = totpService.generateRecoveryCodes();

        return new TotpSetupResponse(secret, qrCodeDataUri, recoveryCodes);
    }

    /**
     * Confirms and persists the TOTP secret and backup recovery codes upon successful code verification.
     * If called with an intermediate challengeToken, finishes authentication and establishes a full session.
     */
    @Transactional(noRollbackFor = ApiException.class)
    public AuthResponse confirmTotp(
            TotpConfirmRequest request,
            String ipAddress,
            String userAgent,
            HttpServletRequest httpRequest
    ) {
        User targetUser = resolveTargetUser(request.challengeToken(), getAuthenticatedUser());
        UserSecuritySettings settings = targetUser.getSecuritySettings();
        if (settings == null) {
            settings = new UserSecuritySettings(targetUser);
            targetUser.setSecuritySettings(settings);
        }

        // 1. Verify code against the secret to be enrolled
        TotpService.TotpVerificationResult result = totpService.verifyCode(request.secret().trim(), request.code().trim(), 0L);
        if (!result.valid()) {
            throw new ApiException(HttpStatus.BAD_REQUEST, ErrorCode.INVALID_TOTP_CODE,
                    "Invalid verification code. Please scan the QR code and try again.");
        }

        // 2. Encrypt secret with AES-256-GCM and persist
        AesGcmEncryptionService.EncryptedPayload encrypted = aesGcmEncryptionService.encrypt(request.secret().trim());
        settings.setTotpEnabled(true);
        settings.setEncryptedTotpSecret(encrypted.base64Ciphertext());
        settings.setTotpEncryptionIv(encrypted.base64Iv());
        settings.setLastTotpTimeStep(result.verifiedTimeStep());
        userSecuritySettingsRepository.save(settings);

        // 3. Hash and store backup recovery codes
        recoveryCodeRepository.deleteByUserId(targetUser.getId());
        for (String code : request.recoveryCodes()) {
            String codeHash = passwordEncoder.encode(code.trim().toUpperCase());
            recoveryCodeRepository.save(new RecoveryCode(targetUser, codeHash));
        }

        auditService.recordEvent(
                targetUser.getId(),
                "TOTP_ENROLLED",
                ipAddress,
                userAgent,
                "User successfully enrolled TOTP multi-factor authentication with backup codes"
        );

        // 4. If part of intermediate challenge login, complete challenge and establish HTTP session
        if (request.challengeToken() != null && !request.challengeToken().isBlank()) {
            String tokenHash = SecurityUtils.sha256(request.challengeToken().trim());
            authChallengeRepository.findByTokenHashAndStatus(tokenHash, AuthChallengeStatus.PENDING)
                    .ifPresent(challenge -> {
                        challenge.setStatus(AuthChallengeStatus.COMPLETED);
                        authChallengeRepository.save(challenge);
                    });
            establishSession(targetUser, httpRequest, ipAddress, userAgent);
        }

        return new AuthResponse(UserResponse.fromEntity(targetUser), "Two-factor authentication successfully configured");
    }

    /**
     * Step 2: Intermediate MFA Challenge Verification & Full Session Establishment.
     * Accepts either a 6-digit TOTP code or a one-time backup recovery code.
     */
    @Transactional(noRollbackFor = ApiException.class)
    public AuthResponse verifyTotp(
            TotpVerifyRequest request,
            String ipAddress,
            String userAgent,
            HttpServletRequest httpRequest
    ) {
        String tokenHash = SecurityUtils.sha256(request.challengeToken().trim());
        AuthChallenge challenge = authChallengeRepository.findByTokenHash(tokenHash)
                .orElseThrow(() -> new ApiException(HttpStatus.UNAUTHORIZED, ErrorCode.INVALID_CHALLENGE,
                        "Authentication challenge is invalid or has expired"));

        if (challenge.getStatus() != AuthChallengeStatus.PENDING) {
            throw new ApiException(HttpStatus.UNAUTHORIZED, ErrorCode.INVALID_CHALLENGE,
                    "Authentication challenge has already been completed or cancelled");
        }

        if (challenge.isExpired()) {
            challenge.setStatus(AuthChallengeStatus.EXPIRED);
            authChallengeRepository.save(challenge);
            throw new ApiException(HttpStatus.UNAUTHORIZED, ErrorCode.CHALLENGE_EXPIRED,
                    "Authentication challenge has expired. Please log in again.");
        }

        if (challenge.getFailedAttempts() >= MAX_CHALLENGE_ATTEMPTS) {
            challenge.setStatus(AuthChallengeStatus.FAILED);
            authChallengeRepository.save(challenge);
            throw new ApiException(HttpStatus.UNAUTHORIZED, ErrorCode.INVALID_CHALLENGE,
                    "Too many failed verification attempts. Authentication challenge cancelled.");
        }

        User user = challenge.getUser();
        UserSecuritySettings settings = user.getSecuritySettings();
        if (settings == null || !settings.isTotpEnabled() || settings.getEncryptedTotpSecret() == null) {
            throw new ApiException(HttpStatus.BAD_REQUEST, ErrorCode.VALIDATION_FAILED,
                    "Two-factor authentication is not configured for this account. Please complete TOTP enrollment.");
        }

        String inputCode = request.code().trim();
        boolean verified = false;

        // 1. Try TOTP 6-digit code verification
        if (inputCode.matches("^\\d{6}$")) {
            String decryptedSecret = aesGcmEncryptionService.decrypt(
                    settings.getEncryptedTotpSecret(),
                    settings.getTotpEncryptionIv()
            );

            TotpService.TotpVerificationResult totpResult = totpService.verifyCode(
                    decryptedSecret,
                    inputCode,
                    settings.getLastTotpTimeStep()
            );

            if (totpResult.valid()) {
                settings.setLastTotpTimeStep(totpResult.verifiedTimeStep());
                userSecuritySettingsRepository.save(settings);
                verified = true;
            }
        }

        // 2. If not verified via TOTP, check if input is a valid backup recovery code
        if (!verified) {
            List<RecoveryCode> activeCodes = recoveryCodeRepository.findActiveCodesByUserId(user.getId());
            for (RecoveryCode recCode : activeCodes) {
                if (passwordEncoder.matches(inputCode.toUpperCase(), recCode.getCodeHash())) {
                    recCode.setUsedAt(Instant.now());
                    recoveryCodeRepository.save(recCode);
                    auditService.recordEvent(
                            user.getId(),
                            "RECOVERY_CODE_USED",
                            ipAddress,
                            userAgent,
                            "User authenticated using a one-time backup recovery code"
                    );
                    verified = true;
                    break;
                }
            }
        }

        // 3. Handle verification failure
        if (!verified) {
            int failedAttempts = challenge.getFailedAttempts() + 1;
            challenge.setFailedAttempts(failedAttempts);

            if (failedAttempts >= MAX_CHALLENGE_ATTEMPTS) {
                challenge.setStatus(AuthChallengeStatus.FAILED);
                authChallengeRepository.save(challenge);
                auditService.recordEvent(
                        user.getId(),
                        "MFA_CHALLENGE_FAILED",
                        ipAddress,
                        userAgent,
                        "MFA challenge locked after 3 consecutive failed verification attempts"
                );
                throw new ApiException(HttpStatus.UNAUTHORIZED, ErrorCode.INVALID_TOTP_CODE,
                        "Too many failed verification attempts. Authentication challenge cancelled.");
            } else {
                authChallengeRepository.save(challenge);
                auditService.recordEvent(
                        user.getId(),
                        "MFA_ATTEMPT_FAILED",
                        ipAddress,
                        userAgent,
                        String.format("Invalid MFA verification attempt %d of %d", failedAttempts, MAX_CHALLENGE_ATTEMPTS)
                );
                throw new ApiException(HttpStatus.UNAUTHORIZED, ErrorCode.INVALID_TOTP_CODE,
                        "Invalid verification code. Please check your authenticator app or backup codes.");
            }
        }

        // 4. Mark challenge completed and establish authenticated HTTP session
        challenge.setStatus(AuthChallengeStatus.COMPLETED);
        authChallengeRepository.save(challenge);

        establishSession(user, httpRequest, ipAddress, userAgent);

        return new AuthResponse(UserResponse.fromEntity(user), "Authentication successful");
    }

    /**
     * Terminate the active HTTP session, clear Spring Security context, and expire session cookies.
     */
    public void logout(HttpServletRequest httpRequest, HttpServletResponse httpResponse, String ipAddress, String userAgent) {
        User currentUser = getAuthenticatedUser();
        if (currentUser != null) {
            auditService.recordEvent(
                    currentUser.getId(),
                    "LOGOUT",
                    ipAddress,
                    userAgent,
                    "User logged out successfully"
            );
        }

        SecurityContextHolder.clearContext();

        HttpSession session = httpRequest.getSession(false);
        if (session != null) {
            session.invalidate();
        }

        ResponseCookie cookie = ResponseCookie.from("JSESSIONID", "")
                .path("/")
                .maxAge(0)
                .httpOnly(true)
                .sameSite("Strict")
                .build();
        httpResponse.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    /**
     * Establishes a secure, authenticated HTTP session with session fixation protection.
     */
    private void establishSession(User user, HttpServletRequest httpRequest, String ipAddress, String userAgent) {
        CustomUserDetails userDetails = new CustomUserDetails(user);
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                userDetails,
                null,
                userDetails.getAuthorities()
        );

        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        SecurityContextHolder.setContext(context);

        if (httpRequest != null) {
            HttpSession session = httpRequest.getSession(true);
            httpRequest.changeSessionId(); // Prevent session fixation attacks
            session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, context);
        }

        auditService.recordEvent(
                user.getId(),
                "LOGIN_SUCCESSFUL",
                ipAddress,
                userAgent,
                "Authentication completed and secure session established. Roles: " + userDetails.getAuthorities()
        );
    }

    private User resolveTargetUser(String challengeToken, User principal) {
        if (challengeToken != null && !challengeToken.isBlank()) {
            String tokenHash = SecurityUtils.sha256(challengeToken.trim());
            AuthChallenge challenge = authChallengeRepository.findByTokenHashAndStatus(tokenHash, AuthChallengeStatus.PENDING)
                    .orElseThrow(() -> new ApiException(HttpStatus.UNAUTHORIZED, ErrorCode.INVALID_CHALLENGE,
                            "Challenge token is invalid or has expired"));
            if (challenge.isExpired()) {
                throw new ApiException(HttpStatus.UNAUTHORIZED, ErrorCode.CHALLENGE_EXPIRED,
                        "Challenge token has expired");
            }
            return challenge.getUser();
        } else if (principal != null) {
            return principal;
        } else {
            throw new ApiException(HttpStatus.UNAUTHORIZED, ErrorCode.UNAUTHORIZED,
                    "Authentication challenge or active session required");
        }
    }

    private User getAuthenticatedUser() {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof CustomUserDetails userDetails) {
            return userDetails.getUser();
        }
        return null;
    }
}
