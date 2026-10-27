/**
 * Ephemeral Cryptographic Handshake Engine ("Clone Key" Protocol)
 *
 * Utilizes the native W3C Web Crypto API (window.crypto.subtle) to derive
 * and encrypt single-use ephemeral authentication credentials directly in the browser.
 * The master/raw password never leaves the client in cleartext, defeating
 * Man-in-the-Middle (MitM) inspection, rogue certificate authorities, and replay attacks.
 */
class CryptoClient {

    /**
     * Converts a Base64-encoded SubjectPublicKeyInfo (X.509) string to a Web Crypto CryptoKey.
     *
     * @param {string} base64PublicKey - Server's ephemeral RSA-2048 public key
     * @returns {Promise<CryptoKey>}
     */
    static async importRsaPublicKey(base64PublicKey) {
        try {
            const cleanKey = base64PublicKey.replace(/\s+/g, '');
            const binaryString = atob(cleanKey);
            const bytes = new Uint8Array(binaryString.length);
            for (let i = 0; i < binaryString.length; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }

            return await window.crypto.subtle.importKey(
                "spki",
                bytes.buffer,
                {
                    name: "RSA-OAEP",
                    hash: "SHA-256"
                },
                false,
                ["encrypt"]
            );
        } catch (error) {
            console.error("Failed to import server ephemeral public key:", error);
            throw new Error("Unable to establish secure cryptographic handshake with server");
        }
    }

    /**
     * Encrypts the user's password cryptographically bound to the serverNonce and timestamp.
     * Produces a single-use "Clone Key" payload.
     *
     * @param {string} password - Raw password entered by user
     * @param {string} serverNonce - Single-use random nonce issued by server
     * @param {number} timestamp - Epoch timestamp issued during pre-login
     * @param {string} base64PublicKey - Ephemeral public key
     * @returns {Promise<string>} Base64-encoded ciphertext ("Clone Key")
     */
    static async generateCloneKey(password, serverNonce, timestamp, base64PublicKey) {
        if (!window.crypto || !window.crypto.subtle) {
            throw new Error("Web Crypto API is not supported in this browser environment. Secure login requires a modern browser.");
        }

        const publicKey = await this.importRsaPublicKey(base64PublicKey);

        // Bind password to the exact serverNonce and timestamp to prevent replay/substitution
        const payload = `${password}:${serverNonce}:${timestamp}`;
        const encodedPayload = new TextEncoder().encode(payload);

        const encryptedBuffer = await window.crypto.subtle.encrypt(
            { name: "RSA-OAEP" },
            publicKey,
            encodedPayload
        );

        // Convert encrypted ArrayBuffer to Base64
        const encryptedBytes = new Uint8Array(encryptedBuffer);
        let binary = '';
        for (let i = 0; i < encryptedBytes.byteLength; i++) {
            binary += String.fromCharCode(encryptedBytes[i]);
        }

        return btoa(binary);
    }
}

window.CryptoClient = CryptoClient;
