import os
import re
import secrets
import sqlite3
import smtplib
import unicodedata
from email.message import EmailMessage
from smtplib import SMTPNotSupportedError
import idna
from flask import Flask, flash, redirect, render_template_string, request, url_for
# --- Config ---
DB = os.environ.get("LAB_DB", "users.db")
SMTP_HOST = os.environ.get("SMTP_HOST", "localhost")
SMTP_PORT = int(os.environ.get("SMTP_PORT", 1025))
FROM_ADDR = os.environ.get("FROM_ADDR", "no-reply@example.test")
BASE_URL = os.environ.get("BASE_URL", "http://127.0.0.1:5000")
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "devsecret")
# --- DB helpers ---
def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            password TEXT,
            reset_token TEXT
        )
        """
    )
    conn.commit()
    conn.close()
def get_user_by_email(email):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT id, email, password, reset_token FROM users WHERE email = ?", (email,))
    row = c.fetchone()
    conn.close()
    return row
def get_user_by_email_normalized_for_reset(email):
    """
    VULNERABLE lookup used in password reset flow.
    It normalizes the *input* by stripping diacritics and lowercasing,
    then compares to all stored emails normalized the same way.
    This intentionally demonstrates the normalization mismatch.
    """
    norm = strip_diacritics(email).lower()
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT id, email, password, reset_token FROM users")
    rows = c.fetchall()
    conn.close()
    for row in rows:
        stored = row[1]
        if strip_diacritics(stored).lower() == norm:
            return row
    return None
def create_user(email, password):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, password))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()
def set_reset_token(user_id, token):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("UPDATE users SET reset_token = ? WHERE id = ?", (token, user_id))
    conn.commit()
    conn.close()
def set_password(user_id, password):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("UPDATE users SET password = ?, reset_token = NULL WHERE id = ?", (password, user_id))
    conn.commit()
    conn.close()
# --- Vulnerable normalization helper ---
def strip_diacritics(s: str) -> str:
    """Normalize string by removing diacritics (accents). This is the intentional bug used by the lab."""
    nfkd = unicodedata.normalize("NFKD", s)
    return "".join([c for c in nfkd if not unicodedata.combining(c)])
# --- Robust envelope fallback helpers ---
def to_ascii_envelope_address(addr: str) -> str:
    """
    Convert an email address to a best-effort ASCII envelope address:
      - domain -> IDNA (punycode/ACE)
      - local-part -> strip diacritics and replace non-ascii / unsafe chars with underscore
    Returns ascii_addr (str).
    """
    if "@" not in addr:
        return addr
    local, host = addr.split("@", 1)
# IDNA encode domain (ACE/punycode)
    try:
        ace_host = idna.encode(host).decode()
    except Exception:
        ace_host = host
# strip diacritics (use same helper)
    safe_local = strip_diacritics(local)
    # replace any remaining non-ascii with underscore
    safe_local = re.sub(r"[^\x00-\x7f]", "_", safe_local)
    # replace characters that are not commonly allowed in local-part with underscore
    safe_local = re.sub(r"[^A-Za-z0-9._%+\-]", "_", safe_local)
# ensure not empty
    if not safe_local:
        safe_local = "user"
return f"{safe_local}@{ace_host}"
def build_email_message(from_addr: str, to_addr: str, subject: str, body: str) -> EmailMessage:
    """Create an EmailMessage object with headers set to show the original recipient in headers/body."""
    msg = EmailMessage()
    # keep the headers human-readable; actual envelope is controlled by SMTP send behavior
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg.set_content(body)
    return msg
def send_email(to_addr: str, subject: str, body: str) -> bool:
    """
    Robust send: try normal send_message; if SMTP server rejects UTF8 addresses,
    fall back to an ASCII-safe envelope recipient and still include full info in body.
    Returns True on success, False on failure.
    """
    msg = build_email_message(FROM_ADDR, to_addr, subject, body)
try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
            s.send_message(msg)  # may raise SMTPNotSupportedError if SMTPUTF8 not supported or UnicodeEncodeError
        app.logger.info("Email sent to %s via %s:%s", to_addr, SMTP_HOST, SMTP_PORT)
        return True
    except (UnicodeEncodeError, SMTPNotSupportedError) as e:
        app.logger.warning("SMTPUTF8 not supported by server (%s). Falling back to ASCII envelope. Error: %s", SMTP_HOST, e)
ascii_recipient = to_ascii_envelope_address(to_addr)
        fallback_body = (
            "[NOTICE] The original recipient required SMTPUTF8 and could not be used as envelope recipient.\n"
            f"Original recipient: {to_addr}\n"
            f"Using ASCII-safe envelope recipient: {ascii_recipient}\n\n"
            f"{body}"
        )
        # build a new message that will be accepted by ASCII-only SMTP servers
        fallback_msg = build_email_message(FROM_ADDR, ascii_recipient, subject, fallback_body)
try:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
                s.send_message(fallback_msg)
            app.logger.info("Email sent to ASCII fallback %s via %s:%s", ascii_recipient, SMTP_HOST, SMTP_PORT)
            return True
        except Exception as e2:
            app.logger.error("Failed to send email even with ASCII fallback: %s", e2)
            return False
    except Exception as e:
        app.logger.error("Unexpected error sending email: %s", e)
        return False
# --- Minimal templates (small, clear) ---
T_INDEX = """
<!doctype html>
<title>Vulnerable IDN ATO Lab</title>
<h2>Vulnerable IDN ATO Lab</h2>
<p><a href="{{ url_for('signup') }}">Signup</a> • <a href="{{ url_for('login') }}">Login</a> • <a href="{{ url_for('forgot') }}">Forgot Password</a></p>
{% with messages = get_flashed_messages() %}
  {% if messages %}
    <ul style="color: green;">
    {% for m in messages %}
      <li>{{ m }}</li>
    {% endfor %}
    </ul>
  {% endif %}
{% endwith %}
"""
T_SIGNUP = """
<!doctype html>
<title>Signup</title>
<h3>Signup</h3>
<form method="post">
  Email: <input name="email" required><br>
  Password: <input name="password" required type="password"><br>
  <button type="submit">Signup</button>
</form>
<p><a href="{{ url_for('index') }}">Home</a></p>
{% with messages = get_flashed_messages(category_filter=["error"]) %}
  {% if messages %}
    <ul style="color: red;">
    {% for m in messages %}
      <li>{{ m }}</li>
    {% endfor %}
    </ul>
  {% endif %}
{% endwith %}
"""
T_LOGIN = """
<!doctype html>
<title>Login</title>
<h3>Login</h3>
<form method="post">
  Email: <input name="email" required><br>
  Password: <input name="password" required type="password"><br>
  <button type="submit">Login</button>
</form>
<p><a href="{{ url_for('index') }}">Home</a></p>
{% with messages = get_flashed_messages(category_filter=["error"]) %}
  {% if messages %}
    <ul style="color: red;">
    {% for m in messages %}
      <li>{{ m }}</li>
    {% endfor %}
    </ul>
  {% endif %}
{% endwith %}
"""
T_FORGOT = """
<!doctype html>
<title>Forgot Password</title>
<h3>Forgot Password</h3>
<form method="post">
  Email: <input name="email" required><br>
  <button type="submit">Send reset</button>
</form>
<p><a href="{{ url_for('index') }}">Home</a></p>
{% with messages = get_flashed_messages(category_filter=["error"]) %}
  {% if messages %}
    <ul style="color: red;">
    {% for m in messages %}
      <li>{{ m }}</li>
    {% endfor %}
    </ul>
  {% endif %}
{% endwith %}
"""
T_RESET = """
<!doctype html>
<title>Reset Password</title>
<h3>Reset Password</h3>
<form method="post">
  New password: <input name="password" required type="password"><br>
  <button type="submit">Reset</button>
</form>
<p><a href="{{ url_for('index') }}">Home</a></p>
{% with messages = get_flashed_messages(category_filter=["error"]) %}
  {% if messages %}
    <ul style="color: red;">
    {% for m in messages %}
      <li>{{ m }}</li>
    {% endfor %}
    </ul>
  {% endif %}
{% endwith %}
"""
# --- Routes ---
@app.route("/")
def index():
    return render_template_string(T_INDEX)
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form["email"].strip()
        password = request.form["password"].strip()
        if not email or not password:
            flash("Email and password are required.", "error")
            return redirect(url_for("signup"))
        ok = create_user(email, password)
        if not ok:
            flash("Email already exists.", "error")
            return redirect(url_for("signup"))
        flash("Account created. You can now log in.")
        return redirect(url_for("index"))
    return render_template_string(T_SIGNUP)
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].strip()
        password = request.form["password"].strip()
        row = get_user_by_email(email)
        if row and row[2] == password:
            flash(f"Login successful for: {email}")
            return redirect(url_for("index"))
        flash("Invalid credentials.", "error")
        return redirect(url_for("login"))
    return render_template_string(T_LOGIN)
@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if request.method == "POST":
        email = request.form["email"].strip()
        if not email:
            flash("Please provide an email address.", "error")
            return redirect(url_for("forgot"))
# VULNERABLE: use normalized lookup for reset (strips diacritics)
        row = get_user_by_email_normalized_for_reset(email)
        if row:
            user_id = row[0]
            stored_email = row[1]
            token = secrets.token_urlsafe(24)
            set_reset_token(user_id, token)
            reset_link = f"{BASE_URL}/reset/{token}"
            body = f"Password reset link:\n\n{reset_link}\n\nIf you did not request this, ignore."
sent = send_email(stored_email, "Password reset", body)
            if sent:
                flash("If an account exists, a reset has been sent (check your inbox).")
            else:
                # do not leak server internals - show a helpful troubleshooting message
                flash("An error occurred sending the reset email. Please try again later or contact support.", "error")
                app.logger.error("Failed to deliver reset email for user id=%s to stored=%s", user_id, stored_email)
            return redirect(url_for("index"))
        else:
            # Always show the same message to avoid account enumeration
            flash("If an account exists, a reset has been sent (check your inbox).")
            return redirect(url_for("index"))
    return render_template_string(T_FORGOT)
@app.route("/reset/<token>", methods=["GET", "POST"])
def reset(token):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE reset_token = ?", (token,))
    r = c.fetchone()
    conn.close()
    if not r:
        flash("Invalid or expired token.", "error")
        return redirect(url_for("index"))
    if request.method == "POST":
        newpw = request.form["password"].strip()
        if not newpw:
            flash("Password required.", "error")
            return redirect(url_for("reset", token=token))
        set_password(r[0], newpw)
        flash("Password updated. You can log in now.")
        return redirect(url_for("index"))
    return render_template_string(T_RESET)
# --- Main ---
if __name__ == "__main__":
    init_db()
    app.logger.info("Starting vulnerable app on %s", BASE_URL)
    app.logger.info("SMTP configured to %s:%s", SMTP_HOST, SMTP_PORT)
    # Flask's built-in server; good enough for local lab/demo
    app.run(debug=True, host="127.0.0.1", port=5000)
