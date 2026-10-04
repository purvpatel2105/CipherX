// CipherX - Page guard
// Protects pages that need a signed-in user, and adds "Messages" + "Logout" to the nav bar.
//
// Load AFTER api.js on: sender.html, receiver.html, dashboard.html
// Do NOT load on: index.html, learn.html, login.html, forgot.html (they are public)
(function () {
    "use strict";

    var LOGIN_PAGE = "login.html";
    var IDLE_LIMIT_MS = 30 * 60 * 1000; // auto sign-out after 30 minutes of inactivity

    function hasSession() {
        try { return !!sessionStorage.getItem("cx_csrf"); } catch (e) { return false; }
    }

    function goToLogin() {
        location.replace(LOGIN_PAGE);
    }

    // 1. Not signed in: leave immediately
    if (!hasSession()) {
        goToLogin();
        return;
    }

    // 2. After logging out, the Back button can show a cached copy of this page.
    //    Check again whenever the page is restored from the browser cache.
    window.addEventListener("pageshow", function (e) {
        if (e.persisted && !hasSession()) goToLogin();
    });

    function doLogout() {
        if (typeof window.logout === "function") {
            window.logout();
        } else { // api.js missing: still sign out locally
            try { sessionStorage.clear(); } catch (e) { /* ignore */ }
            location.href = LOGIN_PAGE;
        }
    }

    // 3. Navigation: "Messages" link and Logout button
    function addNavigation() {
        var onDashboard = location.pathname.split("/").pop() === "dashboard.html";

        var links = document.querySelector(".nav-links");
        var messagesLink = null;
        if (links) {
            messagesLink = links.querySelector('a[href="dashboard.html"]');
            if (!messagesLink) {
                messagesLink = document.createElement("a");
                messagesLink.href = "dashboard.html";
                messagesLink.textContent = "Messages";
                links.insertBefore(messagesLink, links.firstChild);
            }
            if (onDashboard) messagesLink.classList.add("active");
        }

        var actions = document.querySelector(".nav-actions");
        if (actions && !document.getElementById("logoutBtn")) {
            var btn = document.createElement("button");
            btn.type = "button";
            btn.id = "logoutBtn";
            btn.className = "theme-toggle-btn";
            btn.textContent = "Logout";
            btn.style.cssText = "width:auto;padding:0 14px";
            btn.addEventListener("click", doLogout);
            // Put it before the mobile menu button so the menu button stays last
            var burger = document.getElementById("burger");
            actions.insertBefore(btn, burger && burger.parentNode === actions ? burger : null);
        }

        checkSession(onDashboard ? null : messagesLink);
    }

    // 4. Confirm the server session is still valid and show an unread-message badge.
    //    If the session has expired, api.js sends the user to the login page.
    async function checkSession(messagesLink) {
        if (typeof window.api !== "function") return;
        try {
            var r = await window.api("/api/messages/unread-count");
            if (messagesLink && r.unread > 0) {
                var badge = document.createElement("span");
                badge.textContent = r.unread > 99 ? "99+" : String(r.unread);
                badge.setAttribute("aria-label", r.unread + " unread messages");
                badge.style.cssText =
                    "margin-left:6px;padding:1px 7px;border-radius:99px;background:#4ade80;" +
                    "color:#08111f;font:700 11px 'JetBrains Mono',monospace;vertical-align:middle";
                messagesLink.appendChild(badge);
            }
        } catch (e) {
            // Network problems are ignored here. Auth problems are handled inside api.js.
        }
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", addNavigation);
    } else {
        addNavigation();
    }

    // 5. Inactivity timeout: your unlocked private key lives in this tab, so end the
    //    session if nobody is using it.
    var idleTimer = null;
    var lastReset = 0;

    function resetIdleTimer() {
        var now = Date.now();
        if (now - lastReset < 5000 && idleTimer) return; // throttle
        lastReset = now;
        clearTimeout(idleTimer);
        idleTimer = setTimeout(doLogout, IDLE_LIMIT_MS);
    }

    ["mousemove", "keydown", "click", "scroll", "touchstart"].forEach(function (evt) {
        window.addEventListener(evt, resetIdleTimer, { passive: true });
    });
    resetIdleTimer();
})();