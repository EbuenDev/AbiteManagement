package com.enterprise.auth.entity;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "user_security_settings")
public class UserSecuritySettings {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false, unique = true)
    private User user;

    @Column(name = "totp_enabled", nullable = false)
    private boolean totpEnabled = false;

    @Column(name = "encrypted_totp_secret", columnDefinition = "TEXT")
    private String encryptedTotpSecret;

    @Column(name = "totp_encryption_iv", length = 64)
    private String totpEncryptionIv;

    @Column(name = "last_totp_time_step")
    private Long lastTotpTimeStep = 0L;

    @Column(name = "failed_login_count", nullable = false)
    private int failedLoginCount = 0;

    @Column(name = "locked_until")
    private Instant lockedUntil;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    public UserSecuritySettings() {}

    public UserSecuritySettings(User user) {
        this.user = user;
        this.totpEnabled = false;
        this.failedLoginCount = 0;
        this.lastTotpTimeStep = 0L;
        this.updatedAt = Instant.now();
    }

    public UUID getId() {
        return id;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public boolean isTotpEnabled() {
        return totpEnabled;
    }

    public void setTotpEnabled(boolean totpEnabled) {
        this.totpEnabled = totpEnabled;
        this.updatedAt = Instant.now();
    }

    public String getEncryptedTotpSecret() {
        return encryptedTotpSecret;
    }

    public void setEncryptedTotpSecret(String encryptedTotpSecret) {
        this.encryptedTotpSecret = encryptedTotpSecret;
        this.updatedAt = Instant.now();
    }

    public String getTotpEncryptionIv() {
        return totpEncryptionIv;
    }

    public void setTotpEncryptionIv(String totpEncryptionIv) {
        this.totpEncryptionIv = totpEncryptionIv;
        this.updatedAt = Instant.now();
    }

    public Long getLastTotpTimeStep() {
        return lastTotpTimeStep;
    }

    public void setLastTotpTimeStep(Long lastTotpTimeStep) {
        this.lastTotpTimeStep = lastTotpTimeStep;
        this.updatedAt = Instant.now();
    }

    public int getFailedLoginCount() {
        return failedLoginCount;
    }

    public void setFailedLoginCount(int failedLoginCount) {
        this.failedLoginCount = failedLoginCount;
        this.updatedAt = Instant.now();
    }

    public Instant getLockedUntil() {
        return lockedUntil;
    }

    public void setLockedUntil(Instant lockedUntil) {
        this.lockedUntil = lockedUntil;
        this.updatedAt = Instant.now();
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    @PreUpdate
    public void preUpdate() {
        this.updatedAt = Instant.now();
    }
}
