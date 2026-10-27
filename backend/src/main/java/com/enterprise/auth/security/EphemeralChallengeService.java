package com.enterprise.auth.security;

import com.enterprise.auth.exception.ApiException;
import com.enterprise.auth.exception.ErrorCode;
import com.enterprise.auth.util.SecurityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

@Service
public class EphemeralChallengeService {

    private static final Logger log = LoggerFactory.getLogger(EphemeralChallengeService.class);
    private static final long NONCE_TTL_SECONDS = 60;
    private static final String RSA_OAEP_ALGORITHM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    private final Map<String, EphemeralSession> activeSessions = new ConcurrentHashMap<>();

    public record EphemeralSession(
            String serverNonce,
            PrivateKey privateKey,
            Instant expiresAt,
            long createdAtTimestamp
    ) {
        public boolean isExpired() {
            return Instant.now().isAfter(expiresAt);
        }
    }

    public record ChallengeDescriptor(
            String serverNonce,
            String clientSalt,
            String publicKey,
            long timestamp
    ) {}

    /**
     * Generates a new ephemeral key pair and server nonce for pre-login challenge.
     * The nonce is valid for 60 seconds and can only be used once.
     */
    public ChallengeDescriptor generateChallenge(String clientSalt) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair keyPair = generator.generateKeyPair();

            String serverNonce = SecurityUtils.generateSecureRandomHex(32);
            long currentTimestamp = System.currentTimeMillis();
            Instant expiresAt = Instant.now().plus(NONCE_TTL_SECONDS, ChronoUnit.SECONDS);

            EphemeralSession session = new EphemeralSession(
                    serverNonce,
                    keyPair.getPrivate(),
                    expiresAt,
                    currentTimestamp
            );
            activeSessions.put(serverNonce, session);

            String publicKeyBase64 = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());

            return new ChallengeDescriptor(serverNonce, clientSalt, publicKeyBase64, currentTimestamp);
        } catch (NoSuchAlgorithmException e) {
            log.error("RSA KeyPairGenerator algorithm not available", e);
            throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, ErrorCode.INTERNAL_SERVER_ERROR,
                    "Cryptographic subsystem initialization failed");
        }
    }

    /**
     * Atomically consumes and burns the server nonce, decrypting the clone key payload.
     * Enforces anti-replay protection and cryptographic nonce binding.
     *
     * @param serverNonce single-use random nonce issued during pre-login
     * @param base64Ciphertext RSA-OAEP encrypted payload
     * @return decrypted raw password
     */
    public String consumeAndDecrypt(String serverNonce, String base64Ciphertext) {
        if (serverNonce == null || serverNonce.isBlank() || base64Ciphertext == null || base64Ciphertext.isBlank()) {
            throw new ApiException(HttpStatus.BAD_REQUEST, ErrorCode.VALIDATION_FAILED,
                    "Server nonce and encrypted clone key are required");
        }

        // Atomic removal prevents replay attacks
        EphemeralSession session = activeSessions.remove(serverNonce.trim());
        if (session == null) {
            throw new ApiException(HttpStatus.UNAUTHORIZED, ErrorCode.INVALID_CREDENTIALS,
                    "Challenge nonce is invalid or has already been consumed");
        }

        if (session.isExpired()) {
            throw new ApiException(HttpStatus.UNAUTHORIZED, ErrorCode.CHALLENGE_EXPIRED,
                    "Challenge nonce has expired. Please initiate pre-login again.");
        }

        try {
            Cipher cipher = Cipher.getInstance(RSA_OAEP_ALGORITHM);
            OAEPParameterSpec oaepParams = new OAEPParameterSpec(
                    "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT
            );
            cipher.init(Cipher.DECRYPT_MODE, session.privateKey(), oaepParams);

            byte[] decodedCiphertext = Base64.getDecoder().decode(base64Ciphertext.trim());
            byte[] decryptedBytes = cipher.doFinal(decodedCiphertext);
            String payload = new String(decryptedBytes, StandardCharsets.UTF_8);

            // Format can be raw password or "password:serverNonce:timestamp"
            if (payload.contains(":")) {
                String[] parts = payload.split(":", 3);
                String password = parts[0];
                if (parts.length >= 2) {
                    String embeddedNonce = parts[1];
                    if (!serverNonce.trim().equals(embeddedNonce)) {
                        log.warn("Nonce mismatch in decrypted payload: expected {} but got {}", serverNonce, embeddedNonce);
                        throw new ApiException(HttpStatus.UNAUTHORIZED, ErrorCode.INVALID_CREDENTIALS,
                                "Cryptographic challenge binding verification failed");
                    }
                }
                if (parts.length >= 3) {
                    try {
                        long payloadTimestamp = Long.parseLong(parts[2]);
                        long drift = Math.abs(System.currentTimeMillis() - payloadTimestamp);
                        if (drift > 60_000) {
                            throw new ApiException(HttpStatus.UNAUTHORIZED, ErrorCode.CHALLENGE_EXPIRED,
                                    "Challenge timestamp exceeds maximum acceptable clock drift");
                        }
                    } catch (NumberFormatException ignored) {}
                }
                return password;
            }

            return payload;
        } catch (ApiException e) {
            throw e;
        } catch (Exception e) {
            log.warn("Failed to decrypt ephemeral challenge payload: {}", e.getMessage());
            throw new ApiException(HttpStatus.UNAUTHORIZED, ErrorCode.INVALID_CREDENTIALS,
                    "Invalid cryptographic proof payload");
        }
    }

    /**
     * Helper utility for client test harnesses to encrypt password using the ephemeral public key.
     */
    public static String encryptPayload(String plaintext, String base64PublicKey) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(base64PublicKey.trim());
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory factory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = factory.generatePublic(spec);

            Cipher cipher = Cipher.getInstance(RSA_OAEP_ALGORITHM);
            OAEPParameterSpec oaepParams = new OAEPParameterSpec(
                    "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT
            );
            cipher.init(Cipher.ENCRYPT_MODE, publicKey, oaepParams);

            byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            throw new RuntimeException("Failed to encrypt ephemeral payload for testing", e);
        }
    }

    /**
     * Periodic eviction of stale nonces every 60 seconds.
     */
    @Scheduled(fixedRate = 60000)
    public void cleanupExpiredSessions() {
        activeSessions.entrySet().removeIf(entry -> entry.getValue().isExpired());
    }

    public int getActiveSessionCount() {
        return activeSessions.size();
    }
}
