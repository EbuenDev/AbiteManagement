/**
 * Enterprise Application Controller & UI State Orchestrator
 */
document.addEventListener('DOMContentLoaded', () => {

    // --- State Management ---
    let currentUser = null;
    let pendingChallenge = null;
    let pendingEnrollment = null;

    // --- DOM Elements ---
    const authView = document.getElementById('auth-view');
    const dashboardView = document.getElementById('dashboard-view');
    const authAlert = document.getElementById('auth-alert');
    const authAlertText = document.getElementById('auth-alert-text');
    const logoutBtn = document.getElementById('logout-btn');

    // Step 1 Elements
    const step1Form = document.getElementById('step-1-form');
    const loginIdentifierInput = document.getElementById('login-identifier');
    const loginPasswordInput = document.getElementById('login-password');
    const togglePasswordBtn = document.getElementById('toggle-password-btn');
    const step1SubmitBtn = document.getElementById('step-1-submit-btn');
    const step1BtnText = document.getElementById('step-1-btn-text');
    const step1Spinner = document.getElementById('step-1-spinner');
    const step1Indicator = document.getElementById('step-1-indicator');
    const step2Indicator = document.getElementById('step-2-indicator');

    // Step 2 Elements
    const step2Form = document.getElementById('step-2-form');
    const totpInputBox = document.getElementById('totp-input-box');
    const totpCodeInput = document.getElementById('totp-code');
    const recoveryCodeBox = document.getElementById('recovery-code-box');
    const recoveryCodeInput = document.getElementById('recovery-code-input');
    const toggleRecoveryBtn = document.getElementById('toggle-recovery-btn');
    const cancelMfaBtn = document.getElementById('cancel-mfa-btn');
    const step2SubmitBtn = document.getElementById('step-2-submit-btn');
    const step2BtnText = document.getElementById('step-2-btn-text');
    const step2Spinner = document.getElementById('step-2-spinner');

    // Modal Elements (TOTP Setup)
    const totpSetupModal = document.getElementById('totp-setup-modal');
    const modalQrImage = document.getElementById('modal-qr-image');
    const modalManualKey = document.getElementById('modal-manual-key');
    const copySecretBtn = document.getElementById('copy-secret-btn');
    const modalRecoveryCodesGrid = document.getElementById('modal-recovery-codes-grid');
    const modalConfirmForm = document.getElementById('modal-confirm-totp-form');
    const modalVerifyCodeInput = document.getElementById('modal-verify-code');
    const modalAlert = document.getElementById('modal-alert');
    const modalAlertText = document.getElementById('modal-alert-text');
    const modalCancelBtn = document.getElementById('modal-cancel-btn');
    const modalConfirmSubmitBtn = document.getElementById('modal-confirm-submit-btn');
    const modalSpinner = document.getElementById('modal-spinner');

    // Dashboard Elements
    const userAvatarInitials = document.getElementById('user-avatar-initials');
    const userDisplayName = document.getElementById('user-display-name');
    const userDisplayEmail = document.getElementById('user-display-email');
    const userDisplayRole = document.getElementById('user-display-role');
    const userManagementSection = document.getElementById('user-management-section');
    const userTableBody = document.getElementById('user-table-body');
    const refreshUsersBtn = document.getElementById('refresh-users-btn');
    const openCreateUserModalBtn = document.getElementById('open-create-user-modal-btn');

    // Modal Create User Elements
    const createUserModal = document.getElementById('create-user-modal');
    const createUserForm = document.getElementById('create-user-form');
    const newUsernameInput = document.getElementById('new-username');
    const newEmailInput = document.getElementById('new-email');
    const newRoleSelect = document.getElementById('new-role');
    const roleAdminOption = document.getElementById('role-admin-option');
    const newPasswordInput = document.getElementById('new-password');
    const closeCreateUserModalBtn = document.getElementById('close-create-user-modal-btn');
    const createUserAlert = document.getElementById('create-user-alert');
    const createUserAlertText = document.getElementById('create-user-alert-text');
    const createUserSubmitBtn = document.getElementById('create-user-submit-btn');
    const createUserSpinner = document.getElementById('create-user-spinner');

    // --- Helpers ---
    function showAlert(element, textElement, message, type = 'error') {
        textElement.textContent = message;
        element.className = `msg-alert ${type}`;
        element.classList.remove('hidden');
    }

    function hideAlert(element) {
        element.classList.add('hidden');
    }

    function setLoading(btn, btnTextSpan, spinner, isLoading, loadingText = 'Processing...') {
        if (isLoading) {
            btn.disabled = true;
            if (btnTextSpan) btnTextSpan.textContent = loadingText;
            if (spinner) spinner.classList.remove('hidden');
        } else {
            btn.disabled = false;
            if (spinner) spinner.classList.add('hidden');
        }
    }

    // --- View Navigation ---
    function showAuthStep1() {
        authView.classList.remove('hidden');
        dashboardView.classList.add('hidden');
        logoutBtn.classList.add('hidden');

        step1Form.classList.remove('hidden');
        step2Form.classList.add('hidden');

        step1Indicator.className = 'step-col active';
        step2Indicator.className = 'step-col';

        document.getElementById('auth-title').textContent = 'Staff Sign In';
        document.getElementById('auth-subtitle').textContent = 'Authorized medical and administrative personnel only';

        pendingChallenge = null;
        pendingEnrollment = null;
        hideAlert(authAlert);
        loginPasswordInput.value = '';
    }

    function showAuthStep2() {
        step1Form.classList.add('hidden');
        step2Form.classList.remove('hidden');

        step1Indicator.className = 'step-col completed';
        step2Indicator.className = 'step-col active';

        document.getElementById('auth-title').textContent = 'Security Verification';
        document.getElementById('auth-subtitle').textContent = 'Enter verification code to enter portal';

        hideAlert(authAlert);
        totpCodeInput.value = '';
        recoveryCodeInput.value = '';
        totpCodeInput.focus();
    }

    function showDashboard(user) {
        currentUser = user;
        authView.classList.add('hidden');
        dashboardView.classList.remove('hidden');
        logoutBtn.classList.remove('hidden');

        // Populate User Info
        const username = user.username;
        const initials = username.substring(0, 2).toUpperCase();
        userAvatarInitials.textContent = initials;
        userDisplayName.textContent = username;
        userDisplayEmail.textContent = user.email;

        const roles = user.roles || [];
        const primaryRole = roles[0] || 'ROLE_STAFF';
        userDisplayRole.textContent = primaryRole;

        userDisplayRole.className = 'role-tag ' + (
            primaryRole === 'ROLE_SUPER_ADMIN' ? 'super-admin' :
            primaryRole === 'ROLE_ADMIN' ? 'admin' : 'staff'
        );

        // RBAC View Controls
        const isSuperAdmin = roles.includes('ROLE_SUPER_ADMIN');
        const isAdmin = roles.includes('ROLE_ADMIN');

        if (isSuperAdmin || isAdmin) {
            userManagementSection.classList.remove('hidden');
            openCreateUserModalBtn.classList.remove('hidden');

            // Admins can only create Staff; Super Admins can create Admin or Staff
            if (roleAdminOption) {
                roleAdminOption.disabled = !isSuperAdmin;
                roleAdminOption.style.display = isSuperAdmin ? 'block' : 'none';
            }

            loadUsers();
        } else {
            userManagementSection.classList.add('hidden');
            openCreateUserModalBtn.classList.add('hidden');
        }
    }

    // --- Password Toggle ---
    togglePasswordBtn.addEventListener('click', () => {
        const isPassword = loginPasswordInput.type === 'password';
        loginPasswordInput.type = isPassword ? 'text' : 'password';
        togglePasswordBtn.innerHTML = isPassword ? `
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path>
                <line x1="1" y1="1" x2="23" y2="23"></line>
            </svg>` : `
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                <circle cx="12" cy="12" r="3"></circle>
            </svg>`;
    });

    // --- STEP 1: PRIMARY CREDENTIALS SUBMISSION ---
    step1Form.addEventListener('submit', async (e) => {
        e.preventDefault();
        hideAlert(authAlert);

        const identifier = loginIdentifierInput.value.trim();
        const rawPassword = loginPasswordInput.value;

        if (!identifier || !rawPassword) {
            showAlert(authAlert, authAlertText, 'Please provide both username and password.');
            return;
        }

        try {
            setLoading(step1SubmitBtn, step1BtnText, step1Spinner, true, 'Negotiating Ephemeral Proof...');

            // Step 1a: Pre-login challenge handshake
            const preLogin = await ApiClient.preLogin(identifier);

            // Step 1b: Derive client-side "Clone Key" via Web Crypto API (RSA-OAEP)
            setLoading(step1SubmitBtn, step1BtnText, step1Spinner, true, 'Deriving Encrypted Clone Key...');
            const cloneKey = await CryptoClient.generateCloneKey(
                rawPassword,
                preLogin.serverNonce,
                preLogin.timestamp,
                preLogin.publicKey
            );

            // Immediately wipe raw password from input field and memory
            loginPasswordInput.value = '';

            // Step 1c: Submit ephemeral proof
            setLoading(step1SubmitBtn, step1BtnText, step1Spinner, true, 'Verifying Credentials...');
            const loginRes = await ApiClient.login({
                identifier,
                serverNonce: preLogin.serverNonce,
                cloneKey,
                timestamp: preLogin.timestamp
            });

            pendingChallenge = loginRes;

            // Check if user has TOTP enrolled
            if (!loginRes.totpEnrolled) {
                // First-time enrollment required
                setLoading(step1SubmitBtn, step1BtnText, step1Spinner, true, 'Initializing Two-Factor Setup...');
                const setupRes = await ApiClient.setupTotp(loginRes.challengeToken);
                pendingEnrollment = setupRes;
                openTotpSetupModal(setupRes);
            } else {
                // User already has TOTP: proceed to Step 2 verification
                showAuthStep2();
            }

        } catch (error) {
            loginPasswordInput.value = '';
            showAlert(authAlert, authAlertText, error.message || 'Authentication failed. Please verify credentials.');
        } finally {
            setLoading(step1SubmitBtn, step1BtnText, step1Spinner, false);
            step1BtnText.textContent = 'Authenticate & Derive Key';
        }
    });

    // --- STEP 2: TOTP & RECOVERY CODE VERIFICATION ---
    step2Form.addEventListener('submit', async (e) => {
        e.preventDefault();
        hideAlert(authAlert);

        if (!pendingChallenge) {
            showAlert(authAlert, authAlertText, 'Session expired. Please sign in again.');
            showAuthStep1();
            return;
        }

        const isRecoveryMode = !recoveryCodeBox.classList.contains('hidden');
        const code = isRecoveryMode ? recoveryCodeInput.value.trim() : totpCodeInput.value.trim();

        if (!code) {
            showAlert(authAlert, authAlertText, isRecoveryMode ? 'Please enter a backup recovery code.' : 'Please enter the 6-digit code.');
            return;
        }

        try {
            setLoading(step2SubmitBtn, step2BtnText, step2Spinner, true, 'Verifying Code...');

            const authRes = await ApiClient.verifyTotp({
                challengeToken: pendingChallenge.challengeToken,
                code
            });

            showDashboard(authRes.user);

        } catch (error) {
            showAlert(authAlert, authAlertText, error.message || 'Verification failed. Please check your code.');
        } finally {
            setLoading(step2SubmitBtn, step2BtnText, step2Spinner, false);
            step2BtnText.textContent = 'Verify & Enter Dashboard';
        }
    });

    // Auto-advance TOTP input on 6 digits
    totpCodeInput.addEventListener('input', (e) => {
        totpCodeInput.value = totpCodeInput.value.replace(/\D/g, '');
        if (totpCodeInput.value.length === 6) {
            step2Form.dispatchEvent(new Event('submit'));
        }
    });

    // Toggle Recovery Code Mode
    toggleRecoveryBtn.addEventListener('click', () => {
        const isRecovery = !recoveryCodeBox.classList.contains('hidden');
        if (isRecovery) {
            recoveryCodeBox.classList.add('hidden');
            totpInputBox.classList.remove('hidden');
            toggleRecoveryBtn.textContent = 'Use a backup recovery code';
            totpCodeInput.focus();
        } else {
            recoveryCodeBox.classList.remove('hidden');
            totpInputBox.classList.add('hidden');
            toggleRecoveryBtn.textContent = 'Use 6-digit authenticator code';
            recoveryCodeInput.focus();
        }
    });

    cancelMfaBtn.addEventListener('click', () => {
        showAuthStep1();
    });

    // --- TOTP FIRST-TIME SETUP MODAL ---
    function openTotpSetupModal(setupData) {
        modalQrImage.src = setupData.qrCodeDataUri;
        modalManualKey.textContent = setupData.manualKey;

        modalRecoveryCodesGrid.innerHTML = '';
        (setupData.recoveryCodes || []).forEach(code => {
            const chip = document.createElement('div');
            chip.className = 'recovery-code-chip';
            chip.textContent = code;
            modalRecoveryCodesGrid.appendChild(chip);
        });

        modalVerifyCodeInput.value = '';
        hideAlert(modalAlert);
        totpSetupModal.classList.remove('hidden');
        modalVerifyCodeInput.focus();
    }

    copySecretBtn.addEventListener('click', () => {
        if (pendingEnrollment && pendingEnrollment.manualKey) {
            navigator.clipboard.writeText(pendingEnrollment.manualKey);
            copySecretBtn.textContent = 'Copied!';
            setTimeout(() => { copySecretBtn.textContent = 'Copy'; }, 2000);
        }
    });

    modalCancelBtn.addEventListener('click', () => {
        totpSetupModal.classList.add('hidden');
        showAuthStep1();
    });

    modalConfirmForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        hideAlert(modalAlert);

        const code = modalVerifyCodeInput.value.trim();
        if (!code || code.length !== 6) {
            showAlert(modalAlert, modalAlertText, 'Please enter the 6-digit code shown in your app.');
            return;
        }

        try {
            setLoading(modalConfirmSubmitBtn, null, modalSpinner, true);

            const confirmRes = await ApiClient.confirmTotp({
                challengeToken: pendingChallenge.challengeToken,
                secret: pendingEnrollment.manualKey,
                code,
                recoveryCodes: pendingEnrollment.recoveryCodes
            });

            totpSetupModal.classList.add('hidden');
            showDashboard(confirmRes.user);

        } catch (error) {
            showAlert(modalAlert, modalAlertText, error.message || 'Invalid confirmation code.');
        } finally {
            setLoading(modalConfirmSubmitBtn, null, modalSpinner, false);
        }
    });

    // --- LOGOUT ---
    logoutBtn.addEventListener('click', async () => {
        try {
            await ApiClient.logout();
        } catch (error) {
            console.error('Logout error:', error);
        } finally {
            currentUser = null;
            showAuthStep1();
        }
    });

    // --- USER MANAGEMENT (RBAC) ---
    async function loadUsers() {
        try {
            userTableBody.innerHTML = `
                <tr>
                    <td colspan="6" style="text-align: center; padding: 2rem; color: var(--text-muted);">
                        <div class="spinner" style="margin: 0 auto 0.5rem;"></div>
                        Loading accounts...
                    </td>
                </tr>`;

            const pageData = await ApiClient.getUsers(0, 50);
            const users = pageData.content || [];

            if (users.length === 0) {
                userTableBody.innerHTML = `<tr><td colspan="6" style="text-align: center; padding: 2rem; color: var(--text-muted);">No accounts found</td></tr>`;
                return;
            }

            userTableBody.innerHTML = users.map(u => {
                const roles = (u.roles || []).join(', ');
                const statusClass = u.status === 'ACTIVE' ? 'active' :
                                    u.status === 'LOCKED' ? 'locked' : 'suspended';
                const roleTagClass = roles.includes('SUPER_ADMIN') ? 'super-admin' : roles.includes('ADMIN') ? 'admin' : 'staff';
                const createdDate = new Date(u.createdAt).toLocaleDateString();

                let actionButtons = '';
                const isSuperAdmin = currentUser && currentUser.roles && currentUser.roles.includes('ROLE_SUPER_ADMIN');
                const isSelf = currentUser && currentUser.id === u.id;

                if (!isSelf) {
                    if (u.status === 'LOCKED') {
                        actionButtons += `<button class="btn-solid btn-solid-secondary" onclick="window.updateStatus('${u.id}', 'ACTIVE')" style="width:auto; padding: 0.25rem 0.55rem; font-size: 0.75rem;">Unlock</button> `;
                    } else if (u.status === 'ACTIVE') {
                        actionButtons += `<button class="btn-solid btn-solid-danger" onclick="window.updateStatus('${u.id}', 'SUSPENDED')" style="width:auto; padding: 0.25rem 0.55rem; font-size: 0.75rem;">Suspend</button> `;
                    } else if (u.status === 'SUSPENDED') {
                        actionButtons += `<button class="btn-solid btn-solid-secondary" onclick="window.updateStatus('${u.id}', 'ACTIVE')" style="width:auto; padding: 0.25rem 0.55rem; font-size: 0.75rem;">Activate</button> `;
                    }
                }

                return `
                    <tr>
                        <td><strong>${escapeHtml(u.username)}</strong></td>
                        <td>${escapeHtml(u.email)}</td>
                        <td><span class="role-tag ${roleTagClass}">${roles}</span></td>
                        <td><span class="status-pill ${statusClass}">${u.status}</span></td>
                        <td>${createdDate}</td>
                        <td>${actionButtons || '<span style="color:var(--text-dim)">Protected</span>'}</td>
                    </tr>
                `;
            }).join('');

        } catch (error) {
            userTableBody.innerHTML = `<tr><td colspan="6" style="text-align: center; padding: 2rem; color: #fb7185;">Error loading accounts: ${escapeHtml(error.message)}</td></tr>`;
        }
    }

    refreshUsersBtn.addEventListener('click', loadUsers);

    window.updateStatus = async (userId, newStatus) => {
        try {
            await ApiClient.updateUserStatus(userId, newStatus);
            loadUsers();
        } catch (error) {
            alert('Failed to update user status: ' + error.message);
        }
    };

    // --- CREATE USER MODAL ---
    openCreateUserModalBtn.addEventListener('click', () => {
        createUserForm.reset();
        hideAlert(createUserAlert);
        createUserModal.classList.remove('hidden');
        newUsernameInput.focus();
    });

    closeCreateUserModalBtn.addEventListener('click', () => {
        createUserModal.classList.add('hidden');
    });

    createUserForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        hideAlert(createUserAlert);

        const username = newUsernameInput.value.trim();
        const email = newEmailInput.value.trim();
        const role = newRoleSelect.value;
        const initialPassword = newPasswordInput.value;

        if (initialPassword.length < 12) {
            showAlert(createUserAlert, createUserAlertText, 'Initial password must be at least 12 characters.');
            return;
        }

        try {
            setLoading(createUserSubmitBtn, null, createUserSpinner, true);

            await ApiClient.createUser({
                username,
                email,
                role,
                initialPassword
            });

            createUserModal.classList.add('hidden');
            loadUsers();

        } catch (error) {
            showAlert(createUserAlert, createUserAlertText, error.message || 'Failed to create user account.');
        } finally {
            setLoading(createUserSubmitBtn, null, createUserSpinner, false);
        }
    });

    function escapeHtml(string) {
        if (!string) return '';
        return String(string)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    // --- INITIAL SESSION CHECK ---
    async function checkExistingSession() {
        try {
            const user = await ApiClient.getMe();
            showDashboard(user);
        } catch (e) {
            showAuthStep1();
        }
    }

    checkExistingSession();
});
