// CipherX - client-side end-to-end encryption
// Uses only the browser's built-in Web Crypto API. No third-party libraries.
//
//   authSecret(password)               -> login secret sent to the server (never the real password)
//   generateKeyBundle(password)        -> new RSA key pair, private key locked with the password
//   unlockPrivateKey(password, keys)   -> private key (base64) or throws if the password is wrong
//   importPriv(base64)                 -> private CryptoKey for decrypting
//   encryptMessage(text, theirPub, myPub)
//   decryptMessage(message, privateKey)
//
// Load before api.js on login.html, dashboard.html and forgot.html.
const CX = (() => {
    "use strict";

    const enc = new TextEncoder();
    const dec = new TextDecoder("utf-8", { fatal: true });

    const RSA = { name: "RSA-OAEP", hash: "SHA-256" };
    const ITER = 250000;                 // PBKDF2 iterations (changing this breaks existing accounts)
    const AUTH_SALT = "cipherx-auth-v1"; // fixed label for the login secret (do not change)
    const MAX_PLAINTEXT_BYTES = 80000;   // keeps ciphertext under the server's size limit

    // ---- helpers -----------------------------------------------------------

    function ensureSupport() {
        if (!window.crypto || !window.crypto.subtle) {
            throw new Error("Encryption needs a secure context. Open the site via http://127.0.0.1 or HTTPS.");
        }
    }

    // bytes -> base64 (chunked so large messages can't overflow the call stack)
    function b64(buf) {
        const bytes = new Uint8Array(buf);
        let binary = "";
        for (let i = 0; i < bytes.length; i += 8192) {
            binary += String.fromCharCode.apply(null, bytes.subarray(i, i + 8192));
        }
        return btoa(binary);
    }

    // base64 -> bytes (throws a clear error on malformed input)
    function unb64(value) {
        try {
            return Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
        } catch (e) {
            throw new Error("Invalid encrypted data.");
        }
    }

    function requireText(value, name) {
        if (typeof value !== "string" || !value) throw new Error(name + " is required.");
        return value;
    }

    // password -> PBKDF2 key material
    function material(password) {
        return crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits", "deriveKey"]);
    }

    // ---- login secret ------------------------------------------------------

    // A separate value derived from the password. The server hashes THIS, so the real
    // password (which also unlocks your private key) never leaves the browser.
    async function authSecret(password) {
        ensureSupport();
        requireText(password, "Password");
        const bits = await crypto.subtle.deriveBits(
            { name: "PBKDF2", salt: enc.encode(AUTH_SALT), iterations: ITER, hash: "SHA-256" },
            await material(password),
            256
        );
        // "Cx1" prefix guarantees the server's "letters + numbers" rule is always met
        return "Cx1" + Array.from(new Uint8Array(bits), (b) => b.toString(16).padStart(2, "0")).join("");
    }

    // ---- private key protection -------------------------------------------

    // Key that locks / unlocks the private key backup stored on the server
    async function wrapKey(password, salt) {
        return crypto.subtle.deriveKey(
            { name: "PBKDF2", salt: salt, iterations: ITER, hash: "SHA-256" },
            await material(password),
            { name: "AES-GCM", length: 256 },
            false,
            ["encrypt", "decrypt"]
        );
    }

    // Creates a new RSA-2048 key pair. The private key is encrypted with the password
    // before it leaves the browser, so the server only ever stores a locked copy.
    async function generateKeyBundle(password) {
        ensureSupport();
        requireText(password, "Password");

        const pair = await crypto.subtle.generateKey(
            { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
            true,
            ["encrypt", "decrypt"]
        );
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const pkcs8 = await crypto.subtle.exportKey("pkcs8", pair.privateKey);
        const locked = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, await wrapKey(password, salt), pkcs8);

        return {
            public_key: b64(await crypto.subtle.exportKey("spki", pair.publicKey)),
            encrypted_private_key: b64(locked),
            key_salt: b64(salt),
            key_iv: b64(iv)
        };
    }

    // Unlocks the stored private key with the password. Returns base64 PKCS8.
    // Throws if the password is wrong or the stored data was changed.
    async function unlockPrivateKey(password, keys) {
        ensureSupport();
        requireText(password, "Password");
        if (!keys || !keys.key_iv || !keys.key_salt || !keys.encrypted_private_key) {
            throw new Error("Key data is missing.");
        }
        try {
            const plain = await crypto.subtle.decrypt(
                { name: "AES-GCM", iv: unb64(keys.key_iv) },
                await wrapKey(password, unb64(keys.key_salt)),
                unb64(keys.encrypted_private_key)
            );
            return b64(plain);
        } catch (e) {
            throw new Error("Wrong password or corrupted key data.");
        }
    }

    // ---- key import --------------------------------------------------------

    async function importPriv(base64) {
        ensureSupport();
        try {
            return await crypto.subtle.importKey("pkcs8", unb64(requireText(base64, "Private key")), RSA, false, ["decrypt"]);
        } catch (e) {
            throw new Error("Your private key could not be loaded. Please sign in again.");
        }
    }

    async function importPub(base64) {
        try {
            return await crypto.subtle.importKey("spki", unb64(requireText(base64, "Public key")), RSA, false, ["encrypt"]);
        } catch (e) {
            throw new Error("A public key could not be loaded.");
        }
    }

    // ---- messages ----------------------------------------------------------

    // Encrypts text with a fresh random AES-256 key, then locks that key twice:
    // once for the recipient and once for the sender (so the sender can reread it).
    async function encryptMessage(text, recipientPub, myPub) {
        ensureSupport();
        requireText(text, "Message");
        const plain = enc.encode(text);
        if (plain.length > MAX_PLAINTEXT_BYTES) throw new Error("Message is too long.");

        const aes = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]);
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, aes, plain);
        const raw = await crypto.subtle.exportKey("raw", aes);

        const wrap = async (pub) => b64(await crypto.subtle.encrypt(RSA, await importPub(pub), raw));
        return {
            ciphertext: b64(ct),
            iv: b64(iv),
            key_for_recipient: await wrap(recipientPub),
            key_for_sender: await wrap(myPub)
        };
    }

    // m = { wrapped_key, iv, ciphertext } as returned by the inbox / sent endpoints
    async function decryptMessage(m, privateKey) {
        ensureSupport();
        try {
            const raw = await crypto.subtle.decrypt(RSA, privateKey, unb64(m.wrapped_key));
            const aes = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["decrypt"]);
            const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(m.iv) }, aes, unb64(m.ciphertext));
            return dec.decode(plain);
        } catch (e) {
            throw new Error("Could not decrypt this message.");
        }
    }

    return Object.freeze({
        authSecret,
        generateKeyBundle,
        unlockPrivateKey,
        importPriv,
        encryptMessage,
        decryptMessage
    });
})();