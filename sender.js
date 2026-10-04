// CipherX - Sender (passphrase encryption)
// Encrypts in the browser with PBKDF2 + AES-256-GCM, then stores only the ciphertext.
// Load order in sender.html: api.js -> auth.js -> sender.js
(function () {
    "use strict";

    // Reuse the backend address from api.js; fall back if api.js is not loaded
    var API = (typeof API_BASE !== "undefined") ? API_BASE : "http://127.0.0.1:5000";

    var PBKDF2_ITERATIONS = 250000;   // must match receiver.js
    var MAX_PLAINTEXT_BYTES = 80000;  // keeps the ciphertext under the server's size limit
    var MIN_PASSPHRASE = 8;

    var $ = function (id) { return document.getElementById(id); };
    var messageInput = $("message");
    var secretKeyInput = $("secretKey");
    var encryptBtn = $("encryptBtn");
    var sendBtn = $("sendBtn");
    var encryptedSection = $("encryptedSection");
    var encryptedMessage = $("encryptedMessage");
    var sendResult = $("sendResult");
    var messageIdInput = $("messageId");
    var copyBtn = $("copyBtn");
    var statusEl = $("status");

    var encoder = new TextEncoder();
    var encryptedData = null; // { ciphertext, salt, iv } ready to send

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

    // Bytes -> Base64 (chunked so large messages don't overflow the call stack)
    function toBase64(bytes) {
        var data = new Uint8Array(bytes);
        var binary = "";
        for (var i = 0; i < data.length; i += 8192) {
            binary += String.fromCharCode.apply(null, data.subarray(i, i + 8192));
        }
        return btoa(binary);
    }

    // If the user edits the message or passphrase after encrypting, the old
    // ciphertext no longer matches. Reset so stale data can never be sent.
    function invalidate() {
        if (!encryptedData) return;
        encryptedData = null;
        encryptedMessage.value = "";
        encryptedSection.classList.add("hidden");
        sendResult.classList.add("hidden");
        setStatus("Message changed. Please encrypt again.");
    }
    messageInput.addEventListener("input", invalidate);
    secretKeyInput.addEventListener("input", invalidate);

    // ---- ENCRYPT ----
    encryptBtn.addEventListener("click", async function () {
        var message = messageInput.value.trim();
        var password = secretKeyInput.value;

        if (!message || !password) {
            setStatus("⚠️ Please enter both a message and a secret passphrase.");
            return;
        }
        if (password.length < MIN_PASSPHRASE) {
            setStatus("⚠️ Passphrase must be at least " + MIN_PASSPHRASE + " characters.");
            return;
        }
        var plainBytes = encoder.encode(message);
        if (plainBytes.length > MAX_PLAINTEXT_BYTES) {
            setStatus("⚠️ Message is too long. Please shorten it.");
            return;
        }
        if (!window.crypto || !window.crypto.subtle) {
            setStatus("❌ Encryption needs a secure context. Open the site via http://127.0.0.1 or HTTPS.");
            return;
        }

        try {
            setBusy(encryptBtn, true, "Encrypting...");
            setStatus("🔐 Deriving key and encrypting...");

            var salt = crypto.getRandomValues(new Uint8Array(16));
            var iv = crypto.getRandomValues(new Uint8Array(12));

            var passwordKey = await crypto.subtle.importKey(
                "raw", encoder.encode(password), "PBKDF2", false, ["deriveKey"]
            );
            var key = await crypto.subtle.deriveKey(
                { name: "PBKDF2", salt: salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
                passwordKey,
                { name: "AES-GCM", length: 256 },
                false,
                ["encrypt"]
            );
            var ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, key, plainBytes);

            encryptedData = {
                ciphertext: toBase64(ciphertext),
                salt: toBase64(salt),
                iv: toBase64(iv)
            };

            encryptedMessage.value = encryptedData.ciphertext;
            encryptedSection.classList.remove("hidden");
            sendResult.classList.add("hidden");
            setStatus("✅ Encrypted with AES-256-GCM. Click the next button to store it.");
        } catch (err) {
            console.error("Encryption error:", err);
            encryptedData = null;
            setStatus("❌ Encryption failed. Please try again.");
        } finally {
            setBusy(encryptBtn, false);
        }
    });

    // ---- SEND (store ciphertext on the server) ----
    sendBtn.addEventListener("click", async function () {
        if (!encryptedData) {
            setStatus("⚠️ Please encrypt a message first.");
            return;
        }

        var controller = new AbortController();
        var timer = setTimeout(function () { controller.abort(); }, 15000);

        try {
            setBusy(sendBtn, true, "Sending...");
            setStatus("📡 Sending encrypted payload to the server...");

            var response = await fetch(API + "/send", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(encryptedData),
                signal: controller.signal
            });
            var result = await response.json().catch(function () { return {}; });

            if (!response.ok) {
                throw new Error(result.error || "Server error (" + response.status + ")");
            }

            messageIdInput.value = result.message_id;
            sendResult.classList.remove("hidden");
            setStatus("🚀 Stored. Share the Message ID, and send the passphrase through a different channel.");
        } catch (err) {
            console.error("Send error:", err);
            if (err.name === "AbortError") {
                setStatus("❌ The server took too long to respond. Please try again.");
            } else if (err instanceof TypeError) {
                setStatus("❌ Cannot reach the server. Is the backend running?");
            } else {
                setStatus("❌ Failed to send: " + err.message);
            }
        } finally {
            clearTimeout(timer);
            setBusy(sendBtn, false);
        }
    });

    // ---- COPY MESSAGE ID ----
    copyBtn.addEventListener("click", async function () {
        var id = messageIdInput.value;
        if (!id) return;

        var original = copyBtn.textContent;
        try {
            await navigator.clipboard.writeText(id);
            copyBtn.textContent = "Copied ✓";
            setStatus("📋 Message ID copied.");
        } catch (err) {
            messageIdInput.select(); // fallback: select so the user can press Ctrl+C
            setStatus("⚠️ Couldn't copy automatically. The ID is selected, press Ctrl+C.");
        }
        setTimeout(function () { copyBtn.textContent = original; }, 1800);
    });
})();