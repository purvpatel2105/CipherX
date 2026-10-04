// CipherX - API client
// Talks to the Flask backend. Load BEFORE auth.js and your page scripts.
//
//   api(path, { method, body })  -> parsed JSON, or throws an Error with .code and .status
//   logout()                     -> ends the session and returns to login.html
//   clearSession()               -> wipes everything stored in this tab
//
// When you deploy, change API_BASE to your server's address (for example "https://api.yoursite.com").
const API_BASE = "http://127.0.0.1:5000";

(function () {
    "use strict";

    var REQUEST_TIMEOUT_MS = 20000;
    var SESSION_KEYS = ["cx_csrf", "cx_user", "cx_priv", "cx_pub"];

    // Pages that are allowed to be open while logged out (so we never redirect in a loop)
    var PUBLIC_PAGES = ["login.html", "forgot.html", "index.html", "learn.html", ""];

    function currentPage() {
        return location.pathname.split("/").pop();
    }

    function clearSession() {
        SESSION_KEYS.forEach(function (k) {
            try { sessionStorage.removeItem(k); } catch (e) { /* storage unavailable */ }
        });
    }

    function getToken() {
        try { return sessionStorage.getItem("cx_csrf") || ""; } catch (e) { return ""; }
    }

    function makeError(message, status, code) {
        var err = new Error(message);
        err.status = status;
        err.code = code;
        return err;
    }

    async function api(path, options) {
        options = options || {};
        var method = options.method || "GET";

        var headers = { "Content-Type": "application/json" };
        var token = getToken();
        if (token) headers["X-CSRF-Token"] = token;

        var controller = new AbortController();
        var timer = setTimeout(function () { controller.abort(); }, REQUEST_TIMEOUT_MS);

        var res;
        try {
            res = await fetch(API_BASE + path, {
                method: method,
                credentials: "include",
                headers: headers,
                body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
                signal: controller.signal
            });
        } catch (e) {
            if (e.name === "AbortError") {
                throw makeError("The server took too long to respond. Please try again.", 0, "TIMEOUT");
            }
            throw makeError("Cannot reach the server. Is the backend running?", 0, "NETWORK");
        } finally {
            clearTimeout(timer);
        }

        // The server normally returns JSON. If it doesn't (proxy error page, etc.), stay safe.
        var data = {};
        try { data = await res.json(); } catch (e) { data = {}; }

        // Session expired or missing: wipe local data and go to sign-in
        if (res.status === 401 && data.code === "AUTH_REQUIRED") {
            clearSession();
            if (PUBLIC_PAGES.indexOf(currentPage()) === -1) {
                location.href = "login.html";
            }
        }

        if (!res.ok) {
            var message = data.error;
            if (!message) {
                if (res.status === 429) message = "Too many requests. Please wait a moment.";
                else if (res.status >= 500) message = "The server had a problem. Please try again.";
                else message = "Request failed (" + res.status + ").";
            }
            throw makeError(message, res.status, data.code);
        }

        return data;
    }

    async function logout() {
        try { await api("/api/auth/logout", { method: "POST" }); } catch (e) { /* log out locally anyway */ }
        clearSession();
        location.href = "login.html";
    }

    // Expose as globals, which is how the other files call them
    window.api = api;
    window.logout = logout;
    window.clearSession = clearSession;
})();