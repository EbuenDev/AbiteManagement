/**
 * Enterprise Application Controller & UI State Orchestrator
 * Animal Bite Treatment Center (ABTC) - Municipal Health Office
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
    const clinicalStepBar = document.querySelector('.clinical-step-bar');

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
    const forgotPasswordLink = document.getElementById('forgot-password-link');

    // Forgot Password Flow Elements
    const forgotPasswordBox = document.getElementById('forgot-password-box');
    const forgotAlert = document.getElementById('forgot-alert');
    const forgotAlertText = document.getElementById('forgot-alert-text');
    const forgotRequestForm = document.getElementById('forgot-request-form');
    const forgotIdentifierInput = document.getElementById('forgot-identifier');
    const forgotRequestSubmitBtn = document.getElementById('forgot-request-submit-btn');
    const forgotRequestSpinner = document.getElementById('forgot-request-spinner');
    const forgotConfirmForm = document.getElementById('forgot-confirm-form');
    const forgotDevTokenNotice = document.getElementById('forgot-dev-token-notice');
    const forgotDevTokenText = document.getElementById('forgot-dev-token-text');
    const forgotTokenInput = document.getElementById('forgot-token-input');
    const forgotNewPasswordInput = document.getElementById('forgot-new-password');
    const forgotConfirmPasswordInput = document.getElementById('forgot-confirm-password');
    const forgotConfirmSubmitBtn = document.getElementById('forgot-confirm-submit-btn');
    const forgotConfirmSpinner = document.getElementById('forgot-confirm-spinner');
    const backToLoginBtn = document.getElementById('back-to-login-btn');

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

    // Dashboard Navigation & Elements
    const userAvatarInitials = document.getElementById('user-avatar-initials');
    const userDisplayName = document.getElementById('user-display-name');
    const userDisplayEmail = document.getElementById('user-display-email');
    const userDisplayRole = document.getElementById('user-display-role');
    const tabPersonnelBtn = document.getElementById('tab-personnel-btn');
    const tabAuditLogsBtn = document.getElementById('tab-audit-logs-btn');
    const userManagementSection = document.getElementById('user-management-section');
    const auditLogSection = document.getElementById('audit-log-section');
    const userTableBody = document.getElementById('user-table-body');
    const auditTableBody = document.getElementById('audit-table-body');
    const refreshUsersBtn = document.getElementById('refresh-users-btn');
    const refreshAuditBtn = document.getElementById('refresh-audit-btn');
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

    // Modal Admin Reset Password Elements
    const adminResetPwdModal = document.getElementById('admin-reset-pwd-modal');
    const adminResetPwdForm = document.getElementById('admin-reset-pwd-form');
    const adminResetTargetId = document.getElementById('admin-reset-target-id');
    const adminResetTargetUsername = document.getElementById('admin-reset-target-username');
    const adminResetNewPwd = document.getElementById('admin-reset-new-pwd');
    const closeAdminResetModalBtn = document.getElementById('close-admin-reset-modal-btn');
    const adminResetAlert = document.getElementById('admin-reset-alert');
    const adminResetAlertText = document.getElementById('admin-reset-alert-text');
    const adminResetSubmitBtn = document.getElementById('admin-reset-submit-btn');
    const adminResetSpinner = document.getElementById('admin-reset-spinner');

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

        if (clinicalStepBar) clinicalStepBar.classList.remove('hidden');
        step1Form.classList.remove('hidden');
        step2Form.classList.add('hidden');
        forgotPasswordBox.classList.add('hidden');

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
        authView.classList.remove('hidden');
        dashboardView.classList.add('hidden');
        logoutBtn.classList.add('hidden');

        if (clinicalStepBar) clinicalStepBar.classList.remove('hidden');
        step1Form.classList.add('hidden');
        step2Form.classList.remove('hidden');
        forgotPasswordBox.classList.add('hidden');

        step1Indicator.className = 'step-col completed';
        step2Indicator.className = 'step-col active';

        document.getElementById('auth-title').textContent = 'Security Verification';
        document.getElementById('auth-subtitle').textContent = 'Enter verification code to enter portal';

        hideAlert(authAlert);
        totpCodeInput.value = '';
        recoveryCodeInput.value = '';
        totpCodeInput.focus();
    }

    function showForgotPasswordFlow() {
        step1Form.classList.add('hidden');
        step2Form.classList.add('hidden');
        if (clinicalStepBar) clinicalStepBar.classList.add('hidden');
        forgotPasswordBox.classList.remove('hidden');

        forgotRequestForm.classList.remove('hidden');
        forgotConfirmForm.classList.add('hidden');
        forgotRequestForm.reset();
        forgotConfirmForm.reset();
        hideAlert(forgotAlert);

        document.getElementById('auth-title').textContent = 'Clinical Portal Access';
        document.getElementById('auth-subtitle').textContent = 'Identity verification & credential recovery';
        forgotIdentifierInput.focus();
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

        if (isSuperAdmin) {
            tabAuditLogsBtn.classList.remove('hidden');
        } else {
            tabAuditLogsBtn.classList.add('hidden');
        }

        if (isSuperAdmin || isAdmin) {
            userManagementSection.classList.remove('hidden');
            openCreateUserModalBtn.classList.remove('hidden');

            if (roleAdminOption) {
                roleAdminOption.disabled = !isSuperAdmin;
                roleAdminOption.style.display = isSuperAdmin ? 'block' : 'none';
            }

            // Default to personnel directory tab
            activatePersonnelTab();
            loadUsers();
        } else {
            userManagementSection.classList.add('hidden');
            auditLogSection.classList.add('hidden');
            openCreateUserModalBtn.classList.add('hidden');
        }
    }

    // --- Tab Navigation in Dashboard ---
    function activatePersonnelTab() {
        tabPersonnelBtn.classList.add('active');
        tabAuditLogsBtn.classList.remove('active');
        userManagementSection.classList.remove('hidden');
        auditLogSection.classList.add('hidden');
    }

    function activateAuditLogsTab() {
        tabPersonnelBtn.classList.remove('active');
        tabAuditLogsBtn.classList.add('active');
        userManagementSection.classList.add('hidden');
        auditLogSection.classList.remove('hidden');
        loadAuditLogs();
    }

    tabPersonnelBtn.addEventListener('click', activatePersonnelTab);
    tabAuditLogsBtn.addEventListener('click', activateAuditLogsTab);

    // --- Toggle Password Visibility ---
    togglePasswordBtn.addEventListener('click', () => {
        const isPassword = loginPasswordInput.type === 'password';
        loginPasswordInput.type = isPassword ? 'text' : 'password';

        togglePasswordBtn.innerHTML = isPassword
            ? `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                 <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path>
                 <line x1="1" y1="1" x2="23" y2="23"></line>
               </svg>`
            : `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                 <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                 <circle cx="12" cy="12" r="3"></circle>
               </svg>`;
    });

    // --- FORGOT PASSWORD WORKFLOW ---
    forgotPasswordLink.addEventListener('click', () => {
        showForgotPasswordFlow();
    });

    backToLoginBtn.addEventListener('click', () => {
        showAuthStep1();
    });

    forgotRequestForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        hideAlert(forgotAlert);

        const identifier = forgotIdentifierInput.value.trim();
        if (!identifier) return;

        try {
            setLoading(forgotRequestSubmitBtn, null, forgotRequestSpinner, true);

            const res = await ApiClient.requestPasswordReset(identifier);

            forgotRequestForm.classList.add('hidden');
            forgotConfirmForm.classList.remove('hidden');

            if (res.devResetToken) {
                forgotTokenInput.value = res.devResetToken;
                forgotDevTokenText.textContent = `Reset instructions generated. [Dev mode token auto-filled]: ${res.devResetToken.substring(0, 16)}...`;
                forgotDevTokenNotice.classList.remove('hidden');
            } else {
                forgotDevTokenNotice.classList.add('hidden');
            }

            showAlert(forgotAlert, forgotAlertText, res.message, 'success');
            forgotNewPasswordInput.focus();

        } catch (error) {
            showAlert(forgotAlert, forgotAlertText, error.message || 'Unable to process reset request.');
        } finally {
            setLoading(forgotRequestSubmitBtn, null, forgotRequestSpinner, false);
        }
    });

    forgotConfirmForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        hideAlert(forgotAlert);

        const token = forgotTokenInput.value.trim();
        const newPassword = forgotNewPasswordInput.value;
        const confirmPassword = forgotConfirmPasswordInput.value;

        if (!token) {
            showAlert(forgotAlert, forgotAlertText, 'Reset verification token is required.');
            return;
        }

        if (newPassword.length < 12) {
            showAlert(forgotAlert, forgotAlertText, 'Password must be at least 12 characters.');
            return;
        }

        if (newPassword !== confirmPassword) {
            showAlert(forgotAlert, forgotAlertText, 'Passwords do not match.');
            return;
        }

        try {
            setLoading(forgotConfirmSubmitBtn, null, forgotConfirmSpinner, true);

            const res = await ApiClient.confirmPasswordReset(token, newPassword);

            showAuthStep1();
            showAlert(authAlert, authAlertText, res.message || 'Password successfully reset. You may now sign in.', 'success');

        } catch (error) {
            showAlert(forgotAlert, forgotAlertText, error.message || 'Password reset failed.');
        } finally {
            setLoading(forgotConfirmSubmitBtn, null, forgotConfirmSpinner, false);
        }
    });

    // --- STEP 1: LOGIN & EPHEMERAL PROOF HANDSHAKE ---
    step1Form.addEventListener('submit', async (e) => {
        e.preventDefault();
        hideAlert(authAlert);

        const identifier = loginIdentifierInput.value.trim();
        const password = loginPasswordInput.value;

        if (!identifier || !password) {
            showAlert(authAlert, authAlertText, 'Please provide both your identifier and password.');
            return;
        }

        try {
            setLoading(step1SubmitBtn, step1BtnText, step1Spinner, true, 'Negotiating Ephemeral Proof...');

            // Step 1a: Pre-Login handshake to retrieve ephemeral RSA public key & server nonce
            const preLoginData = await ApiClient.preLogin(identifier);

            // Step 1b: Derive ephemeral cryptographic proof in browser via native Web Crypto API
            const cloneKey = await CryptoClient.generateCloneKey(
                password,
                preLoginData.serverNonce,
                preLoginData.timestamp,
                preLoginData.publicKey
            );

            // Step 1c: Primary credential verification
            const loginRes = await ApiClient.login({
                identifier,
                serverNonce: preLoginData.serverNonce,
                cloneKey,
                timestamp: preLoginData.timestamp
            });

            // Intermediate challenge state established
            pendingChallenge = loginRes;

            if (loginRes.totpSetupRequired) {
                // User has not enrolled TOTP yet -> Trigger First-Time Enrollment Modal
                initiateTotpEnrollment(loginRes.challengeToken);
            } else {
                // User has TOTP enrolled -> Advance to Step 2 Verification
                showAuthStep2();
            }

        } catch (error) {
            showAlert(authAlert, authAlertText, error.message || 'Invalid clinical credentials or account locked.');
            loginPasswordInput.value = '';
            loginPasswordInput.focus();
        } finally {
            setLoading(step1SubmitBtn, step1BtnText, step1Spinner, false, 'Sign In & Verify');
        }
    });

    // --- STEP 2: TOTP & RECOVERY CODE VERIFICATION ---
    step2Form.addEventListener('submit', async (e) => {
        e.preventDefault();
        hideAlert(authAlert);

        if (!pendingChallenge) {
            showAlert(authAlert, authAlertText, 'Authentication challenge expired. Please sign in again.');
            showAuthStep1();
            return;
        }

        const isRecovery = !recoveryCodeBox.classList.contains('hidden');
        const code = isRecovery ? recoveryCodeInput.value.trim() : totpCodeInput.value.trim();

        if (!code) {
            showAlert(authAlert, authAlertText, isRecovery ? 'Enter your backup recovery code.' : 'Enter the 6-digit TOTP code.');
            return;
        }

        try {
            setLoading(step2SubmitBtn, step2BtnText, step2Spinner, true, 'Verifying Authenticator Code...');

            const payload = {
                challengeToken: pendingChallenge.challengeToken,
                code: isRecovery ? null : code,
                recoveryCode: isRecovery ? code : null
            };

            const verifyRes = await ApiClient.verifyTotp(payload);

            // Session established securely
            showDashboard(verifyRes.user);

        } catch (error) {
            showAlert(authAlert, authAlertText, error.message || 'Verification failed. Please check your code.');
            if (!isRecovery) {
                totpCodeInput.value = '';
                totpCodeInput.focus();
            }
        } finally {
            setLoading(step2SubmitBtn, step2BtnText, step2Spinner, false, 'Confirm Code & Enter Portal');
        }
    });

    toggleRecoveryBtn.addEventListener('click', () => {
        const isRecoveryActive = !recoveryCodeBox.classList.contains('hidden');
        if (isRecoveryActive) {
            recoveryCodeBox.classList.add('hidden');
            totpInputBox.classList.remove('hidden');
            toggleRecoveryBtn.textContent = 'Use backup recovery code';
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

    // Auto-advance TOTP input when 6 digits are typed
    totpCodeInput.addEventListener('input', (e) => {
        e.target.value = e.target.value.replace(/\D/g, '');
        if (e.target.value.length === 6) {
            step2SubmitBtn.click();
        }
    });

    // --- FIRST-TIME TOTP ENROLLMENT ---
    async function initiateTotpEnrollment(challengeToken) {
        try {
            const setupData = await ApiClient.setupTotp(challengeToken);
            pendingEnrollment = setupData;

            modalQrImage.src = setupData.qrCodeDataUri;
            modalManualKey.textContent = setupData.manualKey;

            modalRecoveryCodesGrid.innerHTML = (setupData.recoveryCodes || []).map(code => `
                <div class="rec-item">${code}</div>
            `).join('');

            hideAlert(modalAlert);
            modalVerifyCodeInput.value = '';
            totpSetupModal.classList.remove('hidden');
            modalVerifyCodeInput.focus();

        } catch (error) {
            showAlert(authAlert, authAlertText, 'Failed to initialize two-factor enrollment: ' + error.message);
            showAuthStep1();
        }
    }

    copySecretBtn.addEventListener('click', () => {
        if (pendingEnrollment && pendingEnrollment.manualKey) {
            navigator.clipboard.writeText(pendingEnrollment.manualKey);
            copySecretBtn.textContent = 'Copied!';
            setTimeout(() => { copySecretBtn.textContent = 'Copy Key'; }, 2000);
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
                        <div class="spinner-ring" style="margin: 0 auto 0.5rem; width: 22px; height: 22px; border-width: 2px;"></div>
                        Loading personnel accounts...
                    </td>
                </tr>`;

            const pageData = await ApiClient.getUsers(0, 50);
            const users = pageData.content || [];

            if (users.length === 0) {
                userTableBody.innerHTML = `<tr><td colspan="6" style="text-align: center; padding: 2rem; color: var(--text-muted);">No accounts found</td></tr>`;
                return;
            }

            const isSuperAdmin = currentUser && currentUser.roles && currentUser.roles.includes('ROLE_SUPER_ADMIN');
            const isAdmin = currentUser && currentUser.roles && currentUser.roles.includes('ROLE_ADMIN');

            userTableBody.innerHTML = users.map(u => {
                const roles = (u.roles || []).join(', ');
                const statusClass = u.status === 'ACTIVE' ? 'active' :
                                    u.status === 'LOCKED' ? 'locked' : 'suspended';
                const roleTagClass = roles.includes('SUPER_ADMIN') ? 'super-admin' : roles.includes('ADMIN') ? 'admin' : 'staff';
                const createdDate = new Date(u.createdAt).toLocaleDateString();

                const isTargetSuperAdmin = (u.roles || []).includes('ROLE_SUPER_ADMIN');
                const isTargetAdmin = (u.roles || []).includes('ROLE_ADMIN');
                const isSelf = currentUser && currentUser.id === u.id;

                // Authorization boundary: Admin cannot modify Super Admin or peer Admins
                const canManage = isSuperAdmin || (isAdmin && !isTargetSuperAdmin && !isTargetAdmin);

                let actionButtons = '<div class="table-actions">';

                if (canManage) {
                    // Reset Password Button
                    actionButtons += `
                        <button class="btn-action btn-action-primary" onclick="window.openAdminResetModal('${u.id}', '${escapeHtml(u.username)}')" title="Reset User Password">
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <circle cx="7.5" cy="15.5" r="5.5"></circle>
                                <path d="m21 2-9.6 9.6"></path>
                                <path d="m15.5 7.5 3 3L22 7l-3-3"></path>
                            </svg>
                            <span>Reset Pwd</span>
                        </button>
                    `;

                    // Status Toggle Button (cannot deactivate self)
                    if (!isSelf) {
                        if (u.status === 'ACTIVE') {
                            actionButtons += `
                                <button class="btn-action btn-action-warning" onclick="window.updateStatus('${u.id}', 'SUSPENDED')" title="Suspend account access">
                                    <span>Suspend</span>
                                </button>
                            `;
                        } else {
                            actionButtons += `
                                <button class="btn-action btn-action-primary" onclick="window.updateStatus('${u.id}', 'ACTIVE')" title="Activate account access">
                                    <span>Activate</span>
                                </button>
                            `;
                        }

                        // Delete Button
                        actionButtons += `
                            <button class="btn-action btn-action-danger" onclick="window.deleteUserAccount('${u.id}', '${escapeHtml(u.username)}')" title="Delete account permanently">
                                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <polyline points="3 6 5 6 21 6"></polyline>
                                    <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                                </svg>
                                <span>Delete</span>
                            </button>
                        `;
                    }
                }

                actionButtons += '</div>';

                return `
                    <tr>
                        <td><strong>${escapeHtml(u.username)}</strong></td>
                        <td>${escapeHtml(u.email)}</td>
                        <td><span class="role-tag ${roleTagClass}">${roles}</span></td>
                        <td><span class="status-pill ${statusClass}">${u.status}</span></td>
                        <td>${createdDate}</td>
                        <td>${actionButtons || '<span style="color:var(--text-dim); font-size: 0.75rem;">Protected</span>'}</td>
                    </tr>
                `;
            }).join('');

        } catch (error) {
            userTableBody.innerHTML = `<tr><td colspan="6" style="text-align: center; padding: 2rem; color: #fb7185;">Error loading accounts: ${escapeHtml(error.message)}</td></tr>`;
        }
    }

    refreshUsersBtn.addEventListener('click', loadUsers);

    // Global action: Status Update
    window.updateStatus = async (userId, newStatus) => {
        try {
            await ApiClient.updateUserStatus(userId, newStatus);
            loadUsers();
        } catch (error) {
            alert('Failed to update user status: ' + error.message);
        }
    };

    // Global action: Delete User Account
    window.deleteUserAccount = async (userId, username) => {
        if (!confirm(`Are you sure you want to permanently delete user account '${username}'? This action is audited.`)) {
            return;
        }

        try {
            await ApiClient.deleteUser(userId);
            loadUsers();
        } catch (error) {
            alert('Failed to delete user account: ' + error.message);
        }
    };

    // Global action: Open Admin Reset Password Modal
    window.openAdminResetModal = (userId, username) => {
        adminResetTargetId.value = userId;
        adminResetTargetUsername.textContent = username;
        adminResetPwdForm.reset();
        hideAlert(adminResetAlert);
        adminResetPwdModal.classList.remove('hidden');
        adminResetNewPwd.focus();
    };

    closeAdminResetModalBtn.addEventListener('click', () => {
        adminResetPwdModal.classList.add('hidden');
    });

    adminResetPwdForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        hideAlert(adminResetAlert);

        const userId = adminResetTargetId.value;
        const newPassword = adminResetNewPwd.value;

        if (newPassword.length < 12) {
            showAlert(adminResetAlert, adminResetAlertText, 'Temporary password must be at least 12 characters.');
            return;
        }

        try {
            setLoading(adminResetSubmitBtn, null, adminResetSpinner, true);

            await ApiClient.adminResetPassword(userId, newPassword);

            adminResetPwdModal.classList.add('hidden');
            alert(`Password for user '${adminResetTargetUsername.textContent}' was reset successfully.`);

        } catch (error) {
            showAlert(adminResetAlert, adminResetAlertText, error.message || 'Failed to reset password.');
        } finally {
            setLoading(adminResetSubmitBtn, null, adminResetSpinner, false);
        }
    });

    // --- SECURITY AUDIT LOGS (SUPER ADMIN ONLY) ---
    async function loadAuditLogs() {
        try {
            auditTableBody.innerHTML = `
                <tr>
                    <td colspan="5" style="text-align: center; padding: 2rem; color: var(--text-muted);">
                        <div class="spinner-ring" style="margin: 0 auto 0.5rem; width: 22px; height: 22px; border-width: 2px;"></div>
                        Loading security audit trail...
                    </td>
                </tr>`;

            const pageData = await ApiClient.getAuditLogs(0, 50);
            const logs = pageData.content || [];

            if (logs.length === 0) {
                auditTableBody.innerHTML = `<tr><td colspan="5" style="text-align: center; padding: 2rem; color: var(--text-muted);">No security events recorded yet</td></tr>`;
                return;
            }

            auditTableBody.innerHTML = logs.map(log => {
                const date = new Date(log.createdAt).toLocaleString();
                const eventType = log.eventType || 'UNKNOWN';

                let badgeClass = 'auth-info';
                if (eventType.includes('SUCCESS') || eventType.includes('ENROLLED') || eventType.includes('COMPLETED')) {
                    badgeClass = 'auth-success';
                } else if (eventType.includes('FAILED') || eventType.includes('LOCKED') || eventType.includes('DELETED')) {
                    badgeClass = 'auth-failed';
                } else if (eventType.includes('ADMIN') || eventType.includes('STATUS')) {
                    badgeClass = 'auth-admin';
                }

                let detailsText = log.details || '';
                try {
                    const parsed = JSON.parse(log.details);
                    if (parsed.message) detailsText = parsed.message;
                } catch (_) {}

                return `
                    <tr>
                        <td style="font-family: var(--font-mono); font-size: 0.78rem; white-space: nowrap;">${date}</td>
                        <td><span class="audit-badge ${badgeClass}">${escapeHtml(eventType)}</span></td>
                        <td style="font-family: var(--font-mono); font-size: 0.75rem;">${escapeHtml(log.userId ? log.userId.substring(0, 8) + '...' : 'ANONYMOUS')}</td>
                        <td style="font-family: var(--font-mono); font-size: 0.78rem;">${escapeHtml(log.ipAddress)}</td>
                        <td style="font-size: 0.8rem; color: #334155;">${escapeHtml(detailsText)}</td>
                    </tr>
                `;
            }).join('');

        } catch (error) {
            auditTableBody.innerHTML = `<tr><td colspan="5" style="text-align: center; padding: 2rem; color: #fb7185;">Error loading audit logs: ${escapeHtml(error.message)}</td></tr>`;
        }
    }

    refreshAuditBtn.addEventListener('click', loadAuditLogs);

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
