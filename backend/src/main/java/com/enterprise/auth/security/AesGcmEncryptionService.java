package com.enterprise.auth.security;

import com.enterprise.auth.exception.ApiException;
import com.enterprise.auth.exception.ErrorCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;

@Service
public class AesGcmEncryptionService {

    private static final Logger log = LoggerFactory.getLogger(AesGcmEncryptionService.class);
    private static final String AES_GCM_ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH_BYTES = 12; // 96 bits recommended for GCM
    private static final int GCM_TAG_LENGTH_BITS = 128; // 128-bit authentication tag

    private final SecretKey masterSecretKey;
    private final SecureRandom secureRandom = new SecureRandom();

    public record EncryptedPayload(String base64Ciphertext, String base64Iv) {}

    public AesGcmEncryptionService(
            @Value("${app.security.master-encryption-key:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}")
            String masterKeyHex
    ) {
        try {
            byte[] keyBytes = HexFormat.of().parseHex(masterKeyHex.trim());
            if (keyBytes.length != 32) {
                throw new IllegalArgumentException("Master encryption key must be exactly 32 bytes (64 hex characters) for AES-256");
            }
            this.masterSecretKey = new SecretKeySpec(keyBytes, "AES");
        } catch (Exception e) {
            log.error("Failed to parse master encryption key", e);
            throw new IllegalStateException("Invalid master encryption key configuration", e);
        }
    }

    /**
     * Encrypts plaintext string using AES-256-GCM with a newly generated random 12-byte IV.
     *
     * @param plaintext data to encrypt
     * @return record containing Base64-encoded ciphertext and Base64-encoded IV
     */
    public EncryptedPayload encrypt(String plaintext) {
        if (plaintext == null || plaintext.isBlank()) {
            throw new IllegalArgumentException("Plaintext to encrypt cannot be null or blank");
        }

        try {
            byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
            secureRandom.nextBytes(iv);

            Cipher cipher = Cipher.getInstance(AES_GCM_ALGORITHM);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
            cipher.init(Cipher.ENCRYPT_MODE, masterSecretKey, parameterSpec);

            byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

            String base64Ciphertext = Base64.getEncoder().encodeToString(ciphertext);
            String base64Iv = Base64.getEncoder().encodeToString(iv);

            return new EncryptedPayload(base64Ciphertext, base64Iv);
        } catch (Exception e) {
            log.error("AES-256-GCM encryption failed", e);
            throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, ErrorCode.INTERNAL_SERVER_ERROR,
                    "Encryption subsystem failure");
        }
    }

    /**
     * Decrypts AES-256-GCM ciphertext using the specified Base64-encoded IV.
     * Verifies the 128-bit authentication tag before returning data.
     *
     * @param base64Ciphertext Base64 ciphertext with authentication tag
     * @param base64Iv Base64 12-byte initialization vector
     * @return decrypted plaintext string
     */
    public String decrypt(String base64Ciphertext, String base64Iv) {
        if (base64Ciphertext == null || base64Iv == null) {
            throw new IllegalArgumentException("Ciphertext and IV cannot be null");
        }

        try {
            byte[] ciphertext = Base64.getDecoder().decode(base64Ciphertext.trim());
            byte[] iv = Base64.getDecoder().decode(base64Iv.trim());

            Cipher cipher = Cipher.getInstance(AES_GCM_ALGORITHM);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
            cipher.init(Cipher.DECRYPT_MODE, masterSecretKey, parameterSpec);

            byte[] plaintextBytes = cipher.doFinal(ciphertext);
            return new String(plaintextBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            log.warn("AES-256-GCM decryption failed or authentication tag mismatch: {}", e.getMessage());
            throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, ErrorCode.INTERNAL_SERVER_ERROR,
                    "Cryptographic verification failed for encrypted data");
        }
    }
}
