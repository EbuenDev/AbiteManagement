# Enterprise Authentication & Security Architecture

## 1. System Overview
This document specifies the enterprise authentication and user management architecture, featuring multi-factor authentication (TOTP), defense-in-depth controls, and an **Ephemeral Challenge-Response ("Clone Key") Proof** mechanism to defeat Man-in-the-Middle (MitM) credential interception and replay attacks.

---

## 2. Ephemeral Challenge-Response ("Clone Key") Authentication

### 2.1 The Problem It Solves
In standard authentication flows, a user's static password or master credential is sent over the wire (even over TLS). If TLS termination is inspected, compromised by a rogue CA, or intercepted via a malicious proxy/middleman, the attacker gains permanent access to the user's static password.

### 2.2 The Solution: Ephemeral Proof ("Clone Key")
Instead of transmitting the static password, the client and server engage in a zero-exposure cryptographic handshake:

1. **Pre-Authentication Phase**:
   - The browser requests a dynamic session challenge from the server:
     `GET /api/auth/pre-login?identifier={username}`
   - The server generates a cryptographically secure 256-bit random nonce (`server_nonce`) with a 60-second time-to-live (TTL) and returns it alongside the user's `client_salt`.

2. **Client-Side Derivation ("The Clone Key")**:
   - The browser derives a client key:
     `ClientKey = PBKDF2-HMAC-SHA256(password, clientSalt, iterations=100,000)`
   - The browser computes a single-use ephemeral proof:
     `EphemeralProof = HMAC-SHA256(ClientKey, serverNonce + timestamp)`
   - The raw password is wiped from browser memory immediately.

3. **Login Submission**:
   - The browser transmits only `{ username, serverNonce, ephemeralProof, timestamp }`.
   - Even if intercepted by a middleman:
     - **Pre-image resistance**: The attacker cannot reverse `EphemeralProof` to recover `ClientKey` or `password`.
     - **Anti-replay**: The `serverNonce` is single-use and destroyed atomically by the server upon first evaluation. Subsequent attempts with the same payload fail immediately.

### 2.3 Stage 4 Concrete Implementation
1. **Pre-Login Handshake (`GET /api/auth/pre-login?identifier=...`)**:
   - Generates an ephemeral RSA-2048 keypair and single-use 256-bit `serverNonce` with 60-second TTL.
   - Defeats user enumeration by generating a deterministic synthetic salt for non-existent users so response payloads and timings remain consistent.
   - Returns `{ serverNonce, clientSalt, publicKey, timestamp }`.

2. **Step 1 Login Verification (`POST /api/auth/login`)**:
   - Supports both Ephemeral Clone Key payload (RSA-OAEP encrypted `{password}:{serverNonce}:{timestamp}`) and direct password (for test harnesses/API integrations).
   - Atomic consumption and burning of `serverNonce` prevents replay attacks.
   - Enforces sliding-window rate limiting via Bucket4j token bucket (5 attempts / min / IP + user).
   - Verifies against Argon2id password hash (`m=65536, t=3, p=1`).
   - Mitigates user-existence timing side-channels via synthetic Argon2 verification against non-existent users.
   - Enforces 5-failure threshold: account is locked for 15 minutes (`locked_until`), logged in `audit_logs` as `ACCOUNT_LOCKED`.
   - On success: issues a 256-bit random `challengeToken` (persisted in `auth_challenges` as SHA-256 hash with 300s TTL) and returns `{ challengeToken, mfaRequired: true, expiresAt }`. No session or security context is established.

---

## 3. Two-Step Authentication & Pending Challenge

Full session establishment is strictly isolated into two distinct phases:

### Step 1: Credential Verification
- Validates the ephemeral login proof.
- Verifies account status (`ACTIVE`, not `LOCKED` or `SUSPENDED`).
- Applies sliding-window rate limiting per IP and username.
- **Does NOT create an authenticated HTTP session or issue authorization privileges.**
- Generates a short-lived `AuthChallenge` record with a 256-bit random token (hashed with SHA-256 in the database) and a 300-second TTL.
- Returns `{ challengeToken, mfaRequired: true, expiresAt }`.

### Step 2: TOTP Verification
- The client submits `{ challengeToken, code }` to `/api/auth/totp/verify`.
- The server retrieves the pending challenge in a database transaction, verifying:
  - The challenge has not expired.
  - The challenge has not already been used (`status == 'PENDING'`).
  - Maximum failed attempts have not been exceeded (max 3 tries).
- The server decrypts the user's TOTP secret (encrypted at rest with AES-256-GCM) and verifies the 6-digit code with clock-skew tolerance (+/- 1 time step).
- **Replay Protection**: The server stores `last_totp_time_step` to reject identical codes in the same 30-second window.
- Upon success:
  - Challenge is atomically marked `COMPLETED`.
  - A secure HTTP session (`JSESSIONID`) is created with session fixation protection (`changeSessionId()`).
  - Response headers include `HttpOnly; Secure; SameSite=Strict`.

### 3.1 Stage 5 Concrete Implementation
1. **AES-256-GCM Vault Service (`AesGcmEncryptionService`)**:
   - Master 256-bit key configured via `app.security.master-encryption-key` (`APP_ENCRYPTION_MASTER_KEY`).
   - Dynamic 12-byte (96-bit) cryptographically random IV generated per encryption operation.
   - Enforces 128-bit authentication tag verification upon decryption (tamper detection).

2. **TOTP Engine & Anti-Replay Defense (`TotpService`)**:
   - Generates 160-bit Base32 secrets and QR codes (`otpauth://` Data URI).
   - Validates 6-digit codes with +/- 1 time-step clock drift allowance (30s window).
   - Anti-replay enforcement: compares `currentTimeStep` against persisted `last_totp_time_step`. Replayed codes within the same window fail immediately.

3. **Backup Recovery Codes (`RecoveryCodeRepository`)**:
   - 8 one-time alphanumeric codes (`XXXX-XXXX`) generated during setup.
   - Hashed with Argon2 / BCrypt before persistence in `recovery_codes` table.
   - Verified atomically during step 2 login; once consumed, marked with timestamp `used_at = now()`.

4. **Session Fixation Defense & State Management**:
   - Step 1 credential check strictly does NOT create an HTTP session.
   - Step 2 MFA completion invokes `request.changeSessionId()` before storing `SecurityContext` in `HttpSession`.
   - Audit logging captures `TOTP_ENROLLED`, `RECOVERY_CODE_USED`, `LOGIN_SUCCESSFUL`, and `LOGOUT`.

---

## 4. SQL Injection Immunity
1. **Parameterized Queries**: All database interactions use Spring Data JPA / Hibernate `PreparedStatement` parameter bindings. Data is never concatenated into SQL strings.
2. **Bean Validation**: Strict regex and length constraints on DTOs filter out SQL control characters at the controller boundary.
3. **Least Privilege**: Application runs under an isolated database user without DDL or superuser rights.

---

## 5. Roles and Privileges
- **ROLE_SUPER_ADMIN**: Manages Admin and Staff accounts, inspects security audit logs, controls authentication policies.
- **ROLE_ADMIN**: Manages Staff accounts, accesses administrative dashboards. Cannot elevate privileges or modify Super Admin accounts.
- **ROLE_STAFF**: Standard business operations; zero access to user administration.

---

## 6. Frontend Architecture & Clinical UI (Stage 6)

### 6.1 Clinical Aesthetic Design
- **Domain Focus**: Designed specifically for the **Animal Bite Treatment Center (ABTC)** clinical portal.
- **Visual Tone**: Clean, calm, medical-grade healthcare UI. High-contrast typography (`Inter`), clean hospital blue (`#0284c7`), clinical teal (`#0d9488`), and soft slate backgrounds (`#f8fafc`).
- **Accessibility**: Avoids distracting neon animations or overly dark cyber styling; emphasizes legibility, WCAG contrast standards, structured forms, and clear step-by-step progress bars.

### 6.2 Browser-Native Web Crypto Engine (`crypto-client.js`)
- Uses `window.crypto.subtle` with zero third-party dependencies.
- Implements the **Clone Key** ephemeral handshake:
  1. Requests `serverNonce`, `clientSalt`, `publicKey`, and `timestamp` from `GET /api/auth/pre-login`.
  2. Binds raw password into `{password}:{serverNonce}:{timestamp}`.
  3. Encrypts payload with `RSA-OAEP` (SHA-256) using the server's ephemeral public key.
  4. Immediately zeroes and clears raw password from input fields and browser memory.
  5. Transmits single-use `cloneKey` to `POST /api/auth/login`.

### 6.3 State & Session Management (`app.js` & `api.js`)
- Automatically reads and attaches `XSRF-TOKEN` header on state-changing API calls.
- Enforces strict two-step progression: Step 1 (Staff Credentials) -> Step 2 (6-digit TOTP / Backup Recovery Code).
- Automatic modal for first-time TOTP enrollment: displays QR code image, manual Base32 key with one-click copy, and 8 one-time backup recovery codes.
- Session verification on load (`GET /api/auth/me`) seamlessly restores dashboard state if an active `JSESSIONID` session exists.
- Role-based dashboard controls: Super Admin and Admin can browse, activate, suspend, or unlock staff accounts; Super Admin can create Admin & Staff, while Admin is restricted to Staff creation.

---

## 7. Administrative User Management & Password Reset (Stage 7)

### 7.1 Cryptographic Password Reset Architecture
- **Raw Token Confidentiality**: Password reset tokens are generated using a 256-bit cryptographically secure random generator (`SecurityUtils.generateSecureRandomHex(32)`). The raw token is **never** stored in the database.
- **SHA-256 Token Hashing**: The database table `password_reset_tokens` only persists the `token_hash` (`VARCHAR(64)` SHA-256 digest). Even a full database dump cannot reveal valid reset tokens.
- **Single-Use & Expiration**: Tokens expire after 15 minutes (`expires_at`) and can only be used once (`used_at IS NOT NULL`). Upon consumption or replacement, old tokens for the user are immediately invalidated.
- **Client Salt Rotation**: When a user's password is reset (either via self-service token or administrator intervention), the user's `client_salt` is rotated, invalidating any pre-computed client proofs.
- **Anti-Enumeration Protections**: The public endpoint `POST /api/auth/password-reset/request` returns the identical uniform response (`"If an active account matching the provided identifier exists, password reset instructions have been generated."`) whether the username/email exists or not.

### 7.2 Strict Role Hierarchy Boundaries
- **Super Administrator (`ROLE_SUPER_ADMIN`)**:
  - Full authority to create, inspect, deactivate, delete, and reset passwords for `ROLE_ADMIN` and `ROLE_STAFF`.
  - Self-Lockout Defense: Super Administrators cannot deactivate or delete their own accounts.
  - Last Super Administrator Guard: Deleting or demoting the last remaining Super Administrator in the system is rejected (`400 Bad Request`).
- **Administrator (`ROLE_ADMIN`)**:
  - Authority restricted exclusively to `ROLE_STAFF` accounts.
  - Strict Boundary: Attempting to reset the password, alter the status, or delete accounts with `ROLE_SUPER_ADMIN` or `ROLE_ADMIN` fails with `403 Forbidden`.
  - Cannot create `ROLE_ADMIN` or `ROLE_SUPER_ADMIN` accounts.
- **Staff (`ROLE_STAFF`)**:
  - Zero access to user administration APIs or administrative UI components.

### 7.3 Super Admin Security Audit Trail Inspection
- Super Administrators can inspect all system security events via `GET /api/audit-logs` (`@PreAuthorize("hasRole('SUPER_ADMIN')")`).
- Dedicated Audit Trail UI displays chronological event logs with visual threat and status badges (`auth-success`, `auth-failed`, `auth-admin`, `auth-info`), capturing client IP, operator/target IDs, event types, and structured JSON context.


