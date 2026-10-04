// CipherX - optional shared helpers (safe on every page, none required)
document.addEventListener("DOMContentLoaded", function () {

    // Footer year (only if the page has <span id="yr">)
    var yr = document.getElementById("yr");
    if (yr) yr.textContent = new Date().getFullYear();

    // Mark the current page's nav link as active (only if none is marked yet)
    var links = document.querySelectorAll(".nav-links a");
    var hasActive = document.querySelector(".nav-links a.active");
    if (!hasActive) {
        var page = location.pathname.split("/").pop() || "index.html";
        links.forEach(function (a) {
            if (a.getAttribute("href") === page) a.classList.add("active");
        });
    }

    // Open external links safely
    document.querySelectorAll('a[href^="http"]').forEach(function (a) {
        if (a.hostname !== location.hostname) {
            a.target = "_blank";
            a.rel = "noopener noreferrer";
        }
    });
});