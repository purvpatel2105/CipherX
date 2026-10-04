"""
CipherX Secure Core v3.0
- Argon2id password hashing, email OTP verification, login lockout
- Unique public user IDs (CX-XXXXXXXX) for finding / messaging users
- End-to-end encrypted messaging: the server stores ONLY ciphertext.
  Encryption/decryption happens in the browser (WebCrypto).
- CSRF protection, rate limiting, security headers, audit log
"""
import functools
import hashlib
import hmac
import logging
import os
import re
import secrets
import smtplib
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from dotenv import load_dotenv
from flask import Flask, g, jsonify, request, session
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.exceptions import HTTPException

load_dotenv()

# ----------------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------------
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY or len(SECRET_KEY) < 32:
    raise RuntimeError(
        "SECRET_KEY missing or too short. Generate one with: "
        "python -c \"import secrets; print(secrets.token_hex(32))\" and put it in .env"
    )

DB_NAME = os.environ.get("DB_NAME", "cipherx.db")
DEV_MODE = os.environ.get("DEV_MODE", "false").lower() == "true"
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "false").lower() == "true"
FRONTEND_ORIGINS = [
    o.strip()
    for o in os.environ.get(
        "FRONTEND_ORIGINS",
        "http://localhost:5500,http://127.0.0.1:5500,http://localhost:3000",
    ).split(",")
    if o.strip()
]

SMTP_HOST = os.environ.get("SMTP_HOST")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER")
SMTP_PASS = os.environ.get("SMTP_PASS")
SMTP_FROM = os.environ.get("SMTP_FROM", SMTP_USER or "no-reply@cipherx.local")

OTP_TTL_MIN = 10
OTP_MAX_ATTEMPTS = 5
OTP_RESEND_COOLDOWN_SEC = 60
MAX_FAILED_LOGINS = 5
LOCK_MINUTES = 15

app = Flask(__name__)
app.config.update(
    SECRET_KEY=SECRET_KEY,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=COOKIE_SECURE,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
    MAX_CONTENT_LENGTH=256 * 1024,  # 256 KB request cap
)
app.json.sort_keys = False

CORS(
    app,
    supports_credentials=True,
    origins=FRONTEND_ORIGINS,
    allow_headers=["Content-Type", "X-CSRF-Token"],
    methods=["GET", "POST", "DELETE", "OPTIONS"],
)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["300 per hour"],
    storage_uri="memory://",  # use redis:// in production
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("cipherx")

ph = PasswordHasher()  # Argon2id with safe defaults
DUMMY_HASH = ph.hash("dummy-password-for-timing")


# ----------------------------------------------------------------------------
# Database helpers
# ----------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        conn = sqlite3.connect(DB_NAME)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    with sqlite3.connect(DB_NAME) as conn:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.executescript(
            """
            -- Passphrase tool (anonymous, share-by-Message-ID)
            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                ciphertext TEXT NOT NULL,
                salt TEXT NOT NULL,
                iv TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                public_id TEXT UNIQUE NOT NULL,
                username TEXT UNIQUE NOT NULL COLLATE NOCASE,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_verified INTEGER NOT NULL DEFAULT 0,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until TEXT,
                -- E2EE key bundle (all generated/encrypted in the browser)
                public_key TEXT NOT NULL,
                encrypted_private_key TEXT NOT NULL,
                key_salt TEXT NOT NULL,
                key_iv TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS email_otps (
                user_id TEXT NOT NULL,
                purpose TEXT NOT NULL,           -- 'verify' | 'reset'
                code_hash TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                PRIMARY KEY (user_id, purpose),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS secure_messages (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                recipient_id TEXT NOT NULL,
                ciphertext TEXT NOT NULL,        -- AES-GCM ciphertext
                iv TEXT NOT NULL,
                key_for_recipient TEXT NOT NULL, -- AES key wrapped with recipient RSA public key
                key_for_sender TEXT NOT NULL,    -- same AES key wrapped with sender public key
                created_at TEXT NOT NULL,
                read_at TEXT,
                sender_deleted INTEGER NOT NULL DEFAULT 0,
                recipient_deleted INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (recipient_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_msg_recipient ON secure_messages(recipient_id, created_at);
            CREATE INDEX IF NOT EXISTS idx_msg_sender ON secure_messages(sender_id, created_at);

            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT,
                event TEXT NOT NULL,
                detail TEXT,
                ip TEXT,
                created_at TEXT NOT NULL
            );
            """
        )
        conn.commit()


# ----------------------------------------------------------------------------
# Utilities
# ----------------------------------------------------------------------------
class ApiError(Exception):
    def __init__(self, message, status=400, code=None):
        super().__init__(message)
        self.message, self.status, self.code = message, status, code


def utcnow():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.isoformat(timespec="seconds")


def parse_iso(s):
    return datetime.fromisoformat(s)


def audit(event, user_id=None, detail=None):
    try:
        get_db().execute(
            "INSERT INTO audit_log (user_id, event, detail, ip, created_at) VALUES (?,?,?,?,?)",
            (user_id, event, detail, get_remote_address(), iso(utcnow())),
        )
        get_db().commit()
    except Exception:  # auditing must never break a request
        log.exception("audit failed")


def json_body():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ApiError("Request body must be valid JSON.")
    return data


def get_str(data, key, max_len, required=True):
    val = data.get(key, "")
    if not isinstance(val, str):
        raise ApiError(f"Invalid value for '{key}'.")
    val = val.strip()
    if required and not val:
        raise ApiError(f"'{key}' is required.")
    if len(val) > max_len:
        raise ApiError(f"'{key}' is too long.")
    return val


USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,20}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]{2,}$")
PUBLIC_ID_RE = re.compile(r"^CX-[A-Z0-9]{8}$")
OTP_RE = re.compile(r"^\d{6}$")
B64_RE = re.compile(r"^[A-Za-z0-9+/=_-]+$")


def validate_username(u):
    if not USERNAME_RE.match(u):
        raise ApiError("Username must be 3-20 characters: letters, numbers, underscore.")


def validate_email(e):
    if not EMAIL_RE.match(e) or len(e) > 254:
        raise ApiError("Enter a valid email address.")


def validate_password(p):
    if not isinstance(p, str) or not (10 <= len(p) <= 128):
        raise ApiError("Password must be 10-128 characters.")
    if not (re.search(r"[A-Za-z]", p) and re.search(r"\d", p)):
        raise ApiError("Password must contain at least one letter and one number.")


def key_bundle(data):
    """Validate the client-generated key bundle."""
    out = {
        "public_key": get_str(data, "public_key", 2000),
        "encrypted_private_key": get_str(data, "encrypted_private_key", 8000),
        "key_salt": get_str(data, "key_salt", 200),
        "key_iv": get_str(data, "key_iv", 200),
    }
    for k, v in out.items():
        if not B64_RE.match(v):
            raise ApiError(f"'{k}' must be base64 encoded.")
    return out


def generate_public_id(db):
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no 0/O/1/I confusion
    for _ in range(20):
        pid = "CX-" + "".join(secrets.choice(alphabet) for _ in range(8))
        if not db.execute("SELECT 1 FROM users WHERE public_id=?", (pid,)).fetchone():
            return pid
    raise ApiError("Could not allocate user ID, try again.", 500)


def public_user(row):
    return {
        "id": row["public_id"],
        "username": row["username"],
        "email": row["email"],
        "created_at": row["created_at"],
    }


# ----------------------------------------------------------------------------
# Email + OTP
# ----------------------------------------------------------------------------
def send_email(to, subject, body):
    if not SMTP_HOST:
        if DEV_MODE:
            print(f"\n[DEV EMAIL] To: {to}\nSubject: {subject}\n{body}\n")
            return
        log.error("SMTP not configured; cannot send email.")
        raise ApiError("Email service unavailable. Please try later.", 503)
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = SMTP_FROM, to, subject
    msg.set_content(body)
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as s:
            s.starttls()
            if SMTP_USER:
                s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)
    except Exception:
        log.exception("SMTP send failed")
        raise ApiError("Could not send email. Please try again.", 503)


def otp_hash(user_id, purpose, code):
    return hmac.new(
        SECRET_KEY.encode(), f"{user_id}:{purpose}:{code}".encode(), hashlib.sha256
    ).hexdigest()


def issue_otp(db, user, purpose):
    row = db.execute(
        "SELECT created_at FROM email_otps WHERE user_id=? AND purpose=?",
        (user["id"], purpose),
    ).fetchone()
    if row and (utcnow() - parse_iso(row["created_at"])).total_seconds() < OTP_RESEND_COOLDOWN_SEC:
        raise ApiError("Please wait a minute before requesting another code.", 429)

    code = f"{secrets.randbelow(10**6):06d}"
    now = utcnow()
    db.execute(
        "INSERT OR REPLACE INTO email_otps (user_id, purpose, code_hash, expires_at, attempts, created_at) "
        "VALUES (?,?,?,?,0,?)",
        (user["id"], purpose, otp_hash(user["id"], purpose, code),
         iso(now + timedelta(minutes=OTP_TTL_MIN)), iso(now)),
    )
    db.commit()

    if purpose == "verify":
        subject, intro = "CipherX - verify your email", "Your verification code is:"
    else:
        subject, intro = "CipherX - password reset code", "Your password reset code is:"
    send_email(
        user["email"], subject,
        f"{intro} {code}\n\nIt expires in {OTP_TTL_MIN} minutes. "
        "If you did not request this, you can ignore this email.",
    )


def check_otp(db, user, purpose, code):
    if not OTP_RE.match(code or ""):
        raise ApiError("Enter the 6-digit code.")
    row = db.execute(
        "SELECT * FROM email_otps WHERE user_id=? AND purpose=?", (user["id"], purpose)
    ).fetchone()
    if not row or parse_iso(row["expires_at"]) < utcnow():
        raise ApiError("Code expired or not found. Request a new one.", 400, "OTP_EXPIRED")
    if row["attempts"] >= OTP_MAX_ATTEMPTS:
        raise ApiError("Too many attempts. Request a new code.", 429, "OTP_LOCKED")
    if not hmac.compare_digest(row["code_hash"], otp_hash(user["id"], purpose, code)):
        db.execute(
            "UPDATE email_otps SET attempts = attempts + 1 WHERE user_id=? AND purpose=?",
            (user["id"], purpose),
        )
        db.commit()
        raise ApiError("Incorrect code.", 400, "OTP_INVALID")
    db.execute("DELETE FROM email_otps WHERE user_id=? AND purpose=?", (user["id"], purpose))
    db.commit()


# ----------------------------------------------------------------------------
# Auth decorator (session + CSRF)
# ----------------------------------------------------------------------------
def login_required(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        uid = session.get("user_id")
        if not uid:
            raise ApiError("Authentication required.", 401, "AUTH_REQUIRED")
        user = get_db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        if not user or not user["is_verified"]:
            session.clear()
            raise ApiError("Authentication required.", 401, "AUTH_REQUIRED")
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            sent = request.headers.get("X-CSRF-Token", "")
            if not sent or not hmac.compare_digest(sent, session.get("csrf", "")):
                raise ApiError("Invalid CSRF token.", 403, "CSRF")
        g.user = user
        return fn(*args, **kwargs)
    return wrapper


# ----------------------------------------------------------------------------
# Hooks & error handlers
# ----------------------------------------------------------------------------
@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    resp.headers["Cache-Control"] = "no-store"
    if COOKIE_SECURE:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return resp


@app.errorhandler(ApiError)
def handle_api_error(e):
    body = {"error": e.message}
    if e.code:
        body["code"] = e.code
    return jsonify(body), e.status


@app.errorhandler(404)
def nf(_e):
    return jsonify({"error": "Not found."}), 404


@app.errorhandler(405)
def mna(_e):
    return jsonify({"error": "Method not allowed."}), 405


@app.errorhandler(413)
def too_big(_e):
    return jsonify({"error": "Request too large."}), 413


@app.errorhandler(429)
def rate_limited(_e):
    return jsonify({"error": "Too many requests. Please slow down."}), 429


@app.errorhandler(Exception)
def unhandled(e):
    # Normal web errors (400, 415, ...) keep their own status code
    if isinstance(e, HTTPException):
        return jsonify({"error": e.name}), e.code
    log.exception("Unhandled error: %s", e)
    return jsonify({"error": "Internal server error."}), 500


# ----------------------------------------------------------------------------
# Routes: health
# ----------------------------------------------------------------------------
@app.route("/")
def home():
    return jsonify({"project": "CipherX Secure Core", "status": "online", "version": "3.0.0"})


# ----------------------------------------------------------------------------
# Routes: auth
# ----------------------------------------------------------------------------
@app.route("/api/auth/register", methods=["POST"])
@limiter.limit("5 per hour")
def register():
    data = json_body()
    username = get_str(data, "username", 20)
    email = get_str(data, "email", 254).lower()
    password = data.get("password", "")
    validate_username(username)
    validate_email(email)
    validate_password(password)
    keys = key_bundle(data)

    db = get_db()
    exists = db.execute(
        "SELECT 1 FROM users WHERE email=? OR username=?", (email, username)
    ).fetchone()
    if exists:
        raise ApiError("Username or email is already in use.", 409)

    user_id = str(uuid.uuid4())
    public_id = generate_public_id(db)
    db.execute(
        "INSERT INTO users (id, public_id, username, email, password_hash, is_verified, "
        "public_key, encrypted_private_key, key_salt, key_iv, created_at) "
        "VALUES (?,?,?,?,?,0,?,?,?,?,?)",
        (user_id, public_id, username, email, ph.hash(password),
         keys["public_key"], keys["encrypted_private_key"], keys["key_salt"], keys["key_iv"],
         iso(utcnow())),
    )
    db.commit()
    audit("register", user_id)

    user = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    issue_otp(db, user, "verify")
    return jsonify({
        "message": "Account created. Check your email for the 6-digit verification code.",
        "email": email,
    }), 201


@app.route("/api/auth/verify-email", methods=["POST"])
@limiter.limit("15 per hour")
def verify_email():
    data = json_body()
    email = get_str(data, "email", 254).lower()
    code = get_str(data, "code", 6)
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if not user:
        raise ApiError("Incorrect code.", 400, "OTP_INVALID")
    if user["is_verified"]:
        return jsonify({"message": "Email already verified. You can log in."})
    check_otp(db, user, "verify", code)
    db.execute("UPDATE users SET is_verified=1 WHERE id=?", (user["id"],))
    db.commit()
    audit("email_verified", user["id"])
    return jsonify({"message": "Email verified. You can now log in.", "user_id": user["public_id"]})


@app.route("/api/auth/resend-otp", methods=["POST"])
@limiter.limit("5 per hour")
def resend_otp():
    data = json_body()
    email = get_str(data, "email", 254).lower()
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if user and not user["is_verified"]:
        issue_otp(db, user, "verify")
    # Same response either way, so emails can't be enumerated
    return jsonify({"message": "If that account needs verification, a new code was sent."})


@app.route("/api/auth/login", methods=["POST"])
@limiter.limit("10 per minute")
def login():
    data = json_body()
    key = get_str(data, "loginKey", 254)
    password = data.get("password", "")
    if not isinstance(password, str) or not password or len(password) > 128:
        raise ApiError("Provide username/email and password.")

    db = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE email=? OR username=?", (key.lower(), key)
    ).fetchone()
    bad = ApiError("Invalid credentials.", 401, "BAD_CREDENTIALS")

    if not user:
        try:  # burn equal time so response timing doesn't reveal valid accounts
            ph.verify(DUMMY_HASH, password)
        except Exception:
            pass
        raise bad

    if user["locked_until"] and parse_iso(user["locked_until"]) > utcnow():
        raise ApiError("Account temporarily locked. Try again later.", 423, "LOCKED")

    try:
        ph.verify(user["password_hash"], password)
    except (VerifyMismatchError, InvalidHashError):
        attempts = user["failed_attempts"] + 1
        locked = iso(utcnow() + timedelta(minutes=LOCK_MINUTES)) if attempts >= MAX_FAILED_LOGINS else None
        db.execute(
            "UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?",
            (0 if locked else attempts, locked, user["id"]),
        )
        db.commit()
        audit("login_failed", user["id"])
        raise bad

    if not user["is_verified"]:
        raise ApiError("Please verify your email first.", 403, "EMAIL_NOT_VERIFIED")

    if ph.check_needs_rehash(user["password_hash"]):
        db.execute("UPDATE users SET password_hash=? WHERE id=?", (ph.hash(password), user["id"]))
    db.execute("UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=?", (user["id"],))
    db.commit()

    session.clear()  # prevents session fixation
    session.permanent = True
    session["user_id"] = user["id"]
    session["csrf"] = secrets.token_urlsafe(32)
    audit("login", user["id"])

    return jsonify({
        "message": "Login successful",
        "user": public_user(user),
        "csrf_token": session["csrf"],
        # Browser decrypts this with the password to unlock the private key
        "keys": {
            "public_key": user["public_key"],
            "encrypted_private_key": user["encrypted_private_key"],
            "key_salt": user["key_salt"],
            "key_iv": user["key_iv"],
        },
    })


@app.route("/api/auth/logout", methods=["POST"])
@login_required
def logout():
    audit("logout", g.user["id"])
    session.clear()
    return jsonify({"message": "Logged out."})


@app.route("/api/auth/me", methods=["GET"])
@login_required
def me():
    return jsonify({"user": public_user(g.user), "csrf_token": session["csrf"]})


@app.route("/api/auth/forgot-password", methods=["POST"])
@limiter.limit("5 per hour")
def forgot_password():
    data = json_body()
    email = get_str(data, "email", 254).lower()
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if user and user["is_verified"]:
        try:
            issue_otp(db, user, "reset")
        except ApiError as e:
            if e.status != 429:
                raise
    return jsonify({"message": "If that email is registered, a reset code was sent."})


@app.route("/api/auth/reset-password", methods=["POST"])
@limiter.limit("10 per hour")
def reset_password():
    """
    Because the private key is encrypted with the OLD password, a reset requires
    the browser to generate a NEW key pair. Messages encrypted to the old key
    cannot be decrypted afterwards. This is inherent to true end-to-end encryption.
    """
    data = json_body()
    email = get_str(data, "email", 254).lower()
    code = get_str(data, "code", 6)
    new_password = data.get("new_password", "")
    validate_password(new_password)
    keys = key_bundle(data)

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if not user or not user["is_verified"]:
        raise ApiError("Incorrect code.", 400, "OTP_INVALID")
    check_otp(db, user, "reset", code)
    db.execute(
        "UPDATE users SET password_hash=?, public_key=?, encrypted_private_key=?, key_salt=?, "
        "key_iv=?, failed_attempts=0, locked_until=NULL WHERE id=?",
        (ph.hash(new_password), keys["public_key"], keys["encrypted_private_key"],
         keys["key_salt"], keys["key_iv"], user["id"]),
    )
    db.commit()
    audit("password_reset", user["id"])
    return jsonify({"message": "Password reset. You can now log in."})


# ----------------------------------------------------------------------------
# Routes: users
# ----------------------------------------------------------------------------
@app.route("/api/users/lookup/<public_id>", methods=["GET"])
@login_required
@limiter.limit("30 per minute")
def lookup_user(public_id):
    public_id = public_id.strip().upper()
    if not PUBLIC_ID_RE.match(public_id):
        raise ApiError("Invalid user ID format.")
    row = get_db().execute(
        "SELECT public_id, username, public_key FROM users WHERE public_id=? AND is_verified=1",
        (public_id,),
    ).fetchone()
    if not row:
        raise ApiError("User not found.", 404)
    return jsonify({"id": row["public_id"], "username": row["username"], "public_key": row["public_key"]})


# ----------------------------------------------------------------------------
# Routes: end-to-end encrypted messaging
# ----------------------------------------------------------------------------
@app.route("/api/messages/send", methods=["POST"])
@login_required
@limiter.limit("30 per minute")
def send_secure_message():
    data = json_body()
    to_id = get_str(data, "recipient_id", 20).upper()
    if not PUBLIC_ID_RE.match(to_id):
        raise ApiError("Invalid recipient ID.")
    ciphertext = get_str(data, "ciphertext", 120_000)
    iv = get_str(data, "iv", 100)
    k_rec = get_str(data, "key_for_recipient", 2000)
    k_snd = get_str(data, "key_for_sender", 2000)
    for name, v in (("ciphertext", ciphertext), ("iv", iv),
                    ("key_for_recipient", k_rec), ("key_for_sender", k_snd)):
        if not B64_RE.match(v):
            raise ApiError(f"'{name}' must be base64 encoded.")

    db = get_db()
    rec = db.execute(
        "SELECT id FROM users WHERE public_id=? AND is_verified=1", (to_id,)
    ).fetchone()
    if not rec:
        raise ApiError("Recipient not found.", 404)
    if rec["id"] == g.user["id"]:
        raise ApiError("You cannot send a message to yourself.")

    mid = str(uuid.uuid4())
    db.execute(
        "INSERT INTO secure_messages (id, sender_id, recipient_id, ciphertext, iv, "
        "key_for_recipient, key_for_sender, created_at) VALUES (?,?,?,?,?,?,?,?)",
        (mid, g.user["id"], rec["id"], ciphertext, iv, k_rec, k_snd, iso(utcnow())),
    )
    db.commit()
    audit("message_sent", g.user["id"], mid)
    return jsonify({"message": "Encrypted message delivered.", "message_id": mid}), 201


def _list_messages(box):
    db = get_db()
    page = max(1, request.args.get("page", 1, type=int))
    limit = min(50, max(1, request.args.get("limit", 20, type=int)))
    offset = (page - 1) * limit
    if box == "inbox":
        rows = db.execute(
            "SELECT m.id, m.ciphertext, m.iv, m.key_for_recipient AS wrapped_key, m.created_at, "
            "m.read_at, u.public_id AS peer_id, u.username AS peer_name "
            "FROM secure_messages m JOIN users u ON u.id = m.sender_id "
            "WHERE m.recipient_id=? AND m.recipient_deleted=0 "
            "ORDER BY m.created_at DESC LIMIT ? OFFSET ?",
            (g.user["id"], limit, offset),
        ).fetchall()
    else:
        rows = db.execute(
            "SELECT m.id, m.ciphertext, m.iv, m.key_for_sender AS wrapped_key, m.created_at, "
            "m.read_at, u.public_id AS peer_id, u.username AS peer_name "
            "FROM secure_messages m JOIN users u ON u.id = m.recipient_id "
            "WHERE m.sender_id=? AND m.sender_deleted=0 "
            "ORDER BY m.created_at DESC LIMIT ? OFFSET ?",
            (g.user["id"], limit, offset),
        ).fetchall()
    return jsonify({"messages": [dict(r) for r in rows], "page": page})


@app.route("/api/messages/inbox", methods=["GET"])
@login_required
def inbox():
    return _list_messages("inbox")


@app.route("/api/messages/sent", methods=["GET"])
@login_required
def sent():
    return _list_messages("sent")


@app.route("/api/messages/<message_id>/read", methods=["POST"])
@login_required
def mark_read(message_id):
    db = get_db()
    cur = db.execute(
        "UPDATE secure_messages SET read_at=? WHERE id=? AND recipient_id=? AND read_at IS NULL",
        (iso(utcnow()), message_id, g.user["id"]),
    )
    db.commit()
    return jsonify({"updated": cur.rowcount})


@app.route("/api/messages/<message_id>", methods=["DELETE"])
@login_required
def delete_message(message_id):
    db = get_db()
    uid = g.user["id"]
    msg = db.execute(
        "SELECT sender_id, recipient_id FROM secure_messages WHERE id=?", (message_id,)
    ).fetchone()
    if not msg or uid not in (msg["sender_id"], msg["recipient_id"]):
        raise ApiError("Message not found.", 404)
    col = "sender_deleted" if msg["sender_id"] == uid else "recipient_deleted"
    db.execute(f"UPDATE secure_messages SET {col}=1 WHERE id=?", (message_id,))
    # Purge physically once both sides have deleted it
    db.execute("DELETE FROM secure_messages WHERE id=? AND sender_deleted=1 AND recipient_deleted=1",
               (message_id,))
    db.commit()
    return jsonify({"message": "Deleted."})


@app.route("/api/messages/unread-count", methods=["GET"])
@login_required
def unread_count():
    n = get_db().execute(
        "SELECT COUNT(*) FROM secure_messages WHERE recipient_id=? AND read_at IS NULL AND recipient_deleted=0",
        (g.user["id"],),
    ).fetchone()[0]
    return jsonify({"unread": n})


# ----------------------------------------------------------------------------
# Passphrase tool endpoints (used by sender.js / receiver.js)
# ----------------------------------------------------------------------------
@app.route("/send", methods=["POST"])
@limiter.limit("20 per minute")
def legacy_send():
    data = json_body()
    ct = get_str(data, "ciphertext", 120_000)
    salt = get_str(data, "salt", 200)
    iv = get_str(data, "iv", 200)
    mid = str(uuid.uuid4())
    db = get_db()
    db.execute("INSERT INTO messages (id, ciphertext, salt, iv) VALUES (?,?,?,?)", (mid, ct, salt, iv))
    db.commit()
    return jsonify({"message": "Stored successfully", "message_id": mid}), 201


@app.route("/receive/<message_id>", methods=["GET"])
@limiter.limit("60 per minute")
def legacy_receive(message_id):
    row = get_db().execute(
        "SELECT ciphertext, salt, iv FROM messages WHERE id=?", (message_id,)
    ).fetchone()
    if row is None:
        raise ApiError("Message not found.", 404)
    return jsonify({"ciphertext": row["ciphertext"], "salt": row["salt"], "iv": row["iv"]})


# ----------------------------------------------------------------------------
init_db()

if __name__ == "__main__":
    print("--------------------------------------------------")
    print("        CipherX Secure Server v3.0 [E2EE Active]  ")
    print("--------------------------------------------------")
    app.run(host="127.0.0.1", port=5000, debug=False)