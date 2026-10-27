package com.enterprise.auth.security;

import com.enterprise.auth.exception.ApiException;
import com.enterprise.auth.exception.ErrorCode;
import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.DefaultCodeVerifier;
import dev.samstevens.totp.code.HashingAlgorithm;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import dev.samstevens.totp.util.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

@Service
public class TotpService {

    private static final Logger log = LoggerFactory.getLogger(TotpService.class);
    private static final String ISSUER_NAME = "EnterpriseAuth";
    private static final int TIME_STEP_SECONDS = 30;

    private final SecretGenerator secretGenerator;
    private final QrGenerator qrGenerator;
    private final CodeVerifier codeVerifier;
    private final TimeProvider timeProvider;
    private final Random random = new Random();

    public record TotpVerificationResult(boolean valid, long verifiedTimeStep, String failureReason) {}

    public TotpService() {
        this.secretGenerator = new DefaultSecretGenerator(32);
        this.qrGenerator = new ZxingPngQrGenerator();
        this.timeProvider = new SystemTimeProvider();

        DefaultCodeGenerator codeGenerator = new DefaultCodeGenerator(HashingAlgorithm.SHA1, 6);
        DefaultCodeVerifier verifier = new DefaultCodeVerifier(codeGenerator, timeProvider);
        verifier.setTimePeriod(TIME_STEP_SECONDS);
        verifier.setAllowedTimePeriodDiscrepancy(1); // Allow +/- 1 window for clock drift
        this.codeVerifier = verifier;
    }

    /**
     * Generates a new 160-bit Base32 TOTP secret.
     */
    public String generateSecret() {
        return secretGenerator.generate();
    }

    /**
     * Generates a PNG QR Code as a Data URI (e.g. data:image/png;base64,...).
     */
    public String generateQrCodeDataUri(String username, String secret) {
        try {
            QrData data = new QrData.Builder()
                    .label(username)
                    .secret(secret)
                    .issuer(ISSUER_NAME)
                    .algorithm(HashingAlgorithm.SHA1)
                    .digits(6)
                    .period(TIME_STEP_SECONDS)
                    .build();

            byte[] imageData = qrGenerator.generate(data);
            return Utils.getDataUriForImage(imageData, qrGenerator.getImageMimeType());
        } catch (Exception e) {
            log.error("Failed to generate TOTP QR Code for user '{}'", username, e);
            throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, ErrorCode.INTERNAL_SERVER_ERROR,
                    "Failed to generate two-factor QR code");
        }
    }

    /**
     * Verifies a 6-digit TOTP code against the Base32 secret, enforcing clock skew tolerance and replay protection.
     *
     * @param secret Base32 decrypted secret
     * @param code 6-digit verification code
     * @param lastTimeStep the most recent time step successfully consumed by this user
     * @return TotpVerificationResult containing verification outcome and current time step
     */
    public TotpVerificationResult verifyCode(String secret, String code, Long lastTimeStep) {
        if (code == null || !code.trim().matches("^\\d{6}$")) {
            return new TotpVerificationResult(false, 0L, "Code must be exactly 6 numeric digits");
        }

        long currentTimeStep = timeProvider.getTime() / TIME_STEP_SECONDS;

        // Anti-replay check: reject codes consumed in the same or earlier time step
        if (lastTimeStep != null && currentTimeStep <= lastTimeStep) {
            log.warn("TOTP code replay detected for time step {}", currentTimeStep);
            return new TotpVerificationResult(false, currentTimeStep, "Code has already been consumed in this time window. Please wait for the next 30-second token.");
        }

        boolean isValid = codeVerifier.isValidCode(secret, code.trim());
        if (!isValid) {
            return new TotpVerificationResult(false, currentTimeStep, "Invalid verification code");
        }

        return new TotpVerificationResult(true, currentTimeStep, null);
    }

    /**
     * Generates 8 one-time alphanumeric recovery codes in format 'XXXX-XXXX'.
     */
    public List<String> generateRecoveryCodes() {
        String chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // Removed ambiguous chars like 0, O, 1, I
        List<String> codes = new ArrayList<>(8);
        for (int i = 0; i < 8; i++) {
            StringBuilder sb = new StringBuilder();
            for (int j = 0; j < 8; j++) {
                if (j == 4) {
                    sb.append('-');
                }
                sb.append(chars.charAt(random.nextInt(chars.length())));
            }
            codes.add(sb.toString());
        }
        return codes;
    }
}
