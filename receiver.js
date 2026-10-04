// CipherX - Receiver (passphrase decryption)
// Fetches the ciphertext by Message ID, then decrypts it in the browser.
// Load order in receiver.html: api.js -> auth.js -> receiver.js
(function () {
    "use strict";

    // Reuse the backend address from api.js; fall back if api.js is not loaded
    var API = (typeof API_BASE !== "undefined") ? API_BASE : "http://127.0.0.1:5000";

    var PBKDF2_ITERATIONS = 250000; // must match sender.js
    var ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

    var $ = function (id) { return document.getElementById(id); };
    var messageIdInput = $("messageId");
    var fetchBtn = $("fetchBtn");
    var encryptedSection = $("encryptedSection");
    var encryptedMessage = $("encryptedMessage");
    var secretKeyInput = $("secretKey");
    var decryptBtn = $("decryptBtn");
    var decryptedSection = $("decryptedSection");
    var decryptedMessage = $("decryptedMessage");
    var statusEl = $("status");

    var encoder = new TextEncoder();
    var decoder = new TextDecoder("utf-8", { fatal: true });
    var receivedData = null; // { ciphertext, salt, iv }

    function setStatus(text) { statusEl.textContent = text; }

    function setBusy(btn, busy, label) {
        if (busy) {
            btn.dataset.label = btn.textContent;
            btn.textContent = label;
        } else if (btn.dataset.label) {
            btn.textContent = btn.dataset.label;
        }
        btn.disabled = busy;
        btn.style.opacity = busy ? "0.7" : "1";
    }

    // Base64 -> bytes (throws if the data is not valid Base64)
    function fromBase64(value) {
        var binary = atob(value);
        var bytes = new Uint8Array(binary.length);
        for (var i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
        return bytes;
    }

    function resetResults() {
        receivedData = null;
        encryptedMessage.value = "";
        decryptedMessage.value = "";
        encryptedSection.classList.add("hidden");
        decryptedSection.classList.add("hidden");
    }

    // A different Message ID means any retrieved or decrypted data is out of date
    messageIdInput.addEventListener("input", function () {
        if (receivedData) {
            resetResults();
            secretKeyInput.value = "";
            setStatus("Message ID changed. Please retrieve the message again.");
        }
    });

    // ---- RETRIEVE ----
    async function retrieve() {
        var messageId = messageIdInput.value.trim();

        if (!messageId) {
            setStatus("⚠️ Please enter the Message ID.");
            return;
        }
        if (!ID_PATTERN.test(messageId)) {
            setStatus("⚠️ That doesn't look like a valid Message ID. Check for missing or extra characters.");
            return;
        }

        var controller = new AbortController();
        var timer = setTimeout(function () { controller.abort(); }, 15000);

        try {
            setBusy(fetchBtn, true, "Retrieving...");
            setStatus("📡 Retrieving the encrypted message...");
            resetResults();

            var response = await fetch(API + "/receive/" + encodeURIComponent(messageId), {
                signal: controller.signal
            });
            var result = await response.json().catch(function () { return {}; });

            if (response.status === 404) {
                throw new Error("No message found with that ID.");
            }
            if (!response.ok) {
                throw new Error(result.error || "Server error (" + response.status + ")");
            }
            if (!result.ciphertext || !result.salt || !result.iv) {
                throw new Error("The server returned incomplete data.");
            }

            receivedData = result;
            encryptedMessage.value = result.ciphertext;
            encryptedSection.classList.remove("hidden");
            secretKeyInput.focus();
            setStatus("✅ Message retrieved. Enter the passphrase to decrypt it.");
        } catch (err) {
            console.error("Retrieve error:", err);
            resetResults();
            if (err.name === "AbortError") {
                setStatus("❌ The server took too long to respond. Please try again.");
            } else if (err instanceof TypeError) {
                setStatus("❌ Cannot reach the server. Is the backend running?");
            } else {
                setStatus("❌ " + err.message);
            }
        } finally {
            clearTimeout(timer);
            setBusy(fetchBtn, false);
        }
    }

    fetchBtn.addEventListener("click", retrieve);
    messageIdInput.addEventListener("keydown", function (e) {
        if (e.key === "Enter") retrieve();
    });

    // ---- DECRYPT ----
    async function decrypt() {
        if (!receivedData) {
            setStatus("⚠️ Please retrieve the message first.");
            return;
        }
        var password = secretKeyInput.value;
        if (!password) {
            setStatus("⚠️ Please enter the secret passphrase.");
            return;
        }
        if (!window.crypto || !window.crypto.subtle) {
            setStatus("❌ Decryption needs a secure context. Open the site via http://127.0.0.1 or HTTPS.");
            return;
        }

        try {
            setBusy(decryptBtn, true, "Decrypting...");
            setStatus("🔓 Deriving key and decrypting...");
            decryptedSection.classList.add("hidden");

            var salt = fromBase64(receivedData.salt);
            var iv = fromBase64(receivedData.iv);
            var ciphertext = fromBase64(receivedData.ciphertext);

            var passwordKey = await crypto.subtle.importKey(
                "raw", encoder.encode(password), "PBKDF2", false, ["deriveKey"]
            );
            var key = await crypto.subtle.deriveKey(
                { name: "PBKDF2", salt: salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
                passwordKey,
                { name: "AES-GCM", length: 256 },
                false,
                ["decrypt"]
            );
            var plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, key, ciphertext);

            decryptedMessage.value = decoder.decode(plaintext);
            decryptedSection.classList.remove("hidden");
            decryptedSection.scrollIntoView({ behavior: "smooth", block: "nearest" });
            setStatus("🎉 Message decrypted successfully.");
        } catch (err) {
            // AES-GCM fails the same way for a wrong passphrase and for tampered data
            console.error("Decryption error:", err);
            decryptedMessage.value = "";
            decryptedSection.classList.add("hidden");
            setStatus("❌ Decryption failed. The passphrase is wrong, or the message was altered.");
        } finally {
            setBusy(decryptBtn, false);
        }
    }

    decryptBtn.addEventListener("click", decrypt);
    secretKeyInput.addEventListener("keydown", function (e) {
        if (e.key === "Enter") decrypt();
    });
})();