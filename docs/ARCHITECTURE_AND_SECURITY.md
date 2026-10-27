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
