/**
 * Enterprise API Client
 * Centralized HTTP service managing Fetch requests, CSRF token propagation,
 * response parsing, and standard error normalization.
 */
class ApiClient {

    /**
     * Extracts CSRF token from the 'XSRF-TOKEN' cookie if set by CookieCsrfTokenRepository.
     */
    static getCsrfToken() {
        const match = document.cookie.match(new RegExp('(^|;\\s*)XSRF-TOKEN=([^;]*)'));
        return match ? decodeURIComponent(match[2]) : null;
    }

    /**
     * Centralized request wrapper with credentials inclusion and error handling.
     */
    static async request(url, options = {}) {
        const headers = {
            'Accept': 'application/json',
            ...(options.headers || {})
        };

        if (options.body && typeof options.body === 'object' && !(options.body instanceof FormData)) {
            headers['Content-Type'] = 'application/json';
            options.body = JSON.stringify(options.body);
        }

        // Attach CSRF token for state-changing HTTP methods
        const method = (options.method || 'GET').toUpperCase();
        if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(method)) {
            const csrfToken = this.getCsrfToken();
            if (csrfToken) {
                headers['X-XSRF-TOKEN'] = csrfToken;
            }
        }

        const config = {
            ...options,
            headers,
            credentials: 'same-origin' // Ensures JSESSIONID cookie is transmitted automatically
        };

        try {
            const response = await fetch(url, config);

            // Handle 204 No Content
            if (response.status === 204) {
                return null;
            }

            const contentType = response.headers.get('content-type') || '';
            const isJson = contentType.includes('application/json');
            const data = isJson ? await response.json() : await response.text();

            if (!response.ok) {
                const errorMessage = (data && data.message) ? data.message : `Request failed with status ${response.status}`;
                const error = new Error(errorMessage);
                error.status = response.status;
                error.data = data;
                throw error;
            }

            return data;
        } catch (error) {
            console.error(`API Error [${url}]:`, error);
            throw error;
        }
    }

    // --- Authentication Endpoints ---

    static async preLogin(identifier) {
        return this.request(`/api/auth/pre-login?identifier=${encodeURIComponent(identifier)}`);
    }

    static async login(payload) {
        return this.request('/api/auth/login', {
            method: 'POST',
            body: payload
        });
    }

    static async setupTotp(challengeToken) {
        const query = challengeToken ? `?challengeToken=${encodeURIComponent(challengeToken)}` : '';
        return this.request(`/api/auth/totp/setup${query}`, {
            method: 'POST'
        });
    }

    static async confirmTotp(payload) {
        return this.request('/api/auth/totp/confirm', {
            method: 'POST',
            body: payload
        });
    }

    static async verifyTotp(payload) {
        return this.request('/api/auth/totp/verify', {
            method: 'POST',
            body: payload
        });
    }

    static async getMe() {
        return this.request('/api/auth/me');
    }

    static async logout() {
        return this.request('/api/auth/logout', {
            method: 'POST'
        });
    }

    // --- User Administration Endpoints ---

    static async getUsers(page = 0, size = 10) {
        return this.request(`/api/users?page=${page}&size=${size}`);
    }

    static async createUser(userData) {
        return this.request('/api/users', {
            method: 'POST',
            body: userData
        });
    }

    static async updateUserStatus(userId, status) {
        return this.request(`/api/users/${encodeURIComponent(userId)}/status`, {
            method: 'PUT',
            body: { status }
        });
    }
}

window.ApiClient = ApiClient;
