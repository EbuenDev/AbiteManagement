package com.enterprise.auth.service;

import com.enterprise.auth.audit.AuditService;
import com.enterprise.auth.dto.request.LoginRequest;
import com.enterprise.auth.dto.response.LoginChallengeResponse;
import com.enterprise.auth.dto.response.PreLoginResponse;
import com.enterprise.auth.entity.AuthChallenge;
import com.enterprise.auth.entity.AuthChallengeStatus;
import com.enterprise.auth.entity.User;
import com.enterprise.auth.entity.UserSecuritySettings;
import com.enterprise.auth.entity.UserStatus;
import com.enterprise.auth.exception.ApiException;
import com.enterprise.auth.exception.ErrorCode;
import com.enterprise.auth.repository.AuthChallengeRepository;
import com.enterprise.auth.repository.UserRepository;
import com.enterprise.auth.security.EphemeralChallengeService;
import com.enterprise.auth.security.RateLimiterService;
import com.enterprise.auth.util.SecurityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

@Service
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);
    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final int LOCKOUT_DURATION_MINUTES = 15;
    private static final int CHALLENGE_TTL_SECONDS = 300; // 5 minutes

    // Dummy Argon2 hash to simulate verification timing when user does not exist
    private static final String DUMMY_HASH = "$argon2id$v=19$m=65536,t=3,p=1$c29tZXNhbHQxMjM0NTY3OA$qM0jLp4o5m1s8f4v6x2y0z1a3b5c7d9e";

    private final UserRepository userRepository;
    private final AuthChallengeRepository authChallengeRepository;
    private final EphemeralChallengeService ephemeralChallengeService;
    private final RateLimiterService rateLimiterService;
    private final PasswordEncoder passwordEncoder;
    private final AuditService auditService;

    public AuthService(
            UserRepository userRepository,
            AuthChallengeRepository authChallengeRepository,
            EphemeralChallengeService ephemeralChallengeService,
            RateLimiterService rateLimiterService,
            PasswordEncoder passwordEncoder,
            AuditService auditService
    ) {
        this.userRepository = userRepository;
        this.authChallengeRepository = authChallengeRepository;
        this.ephemeralChallengeService = ephemeralChallengeService;
        this.rateLimiterService = rateLimiterService;
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

        // Explicitly return pending MFA status; no session or security context created
        return new LoginChallengeResponse(rawChallengeToken, true, challengeExpiry);
    }
}
