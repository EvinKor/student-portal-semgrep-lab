"""
Student Portal Lab - single-file Flask application.
Features: login, grades, attendance, assignment uploads, messaging, own-profile updates.
Demo accounts (change before any real deployment):
  student1 / Student@123
  lecturer1 / Lecturer@123
"""

import os
import re
import secrets
import sqlite3
import uuid
from functools import wraps
from pathlib import Path

from flask import (
    Flask, abort, flash, g, redirect, render_template_string,
    request, session, url_for, send_from_directory
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

APP_DIR = Path(__file__).resolve().parent
DATABASE = APP_DIR / "student_portal.db"
UPLOAD_DIR = APP_DIR / "uploads"
ALLOWED_EXTENSIONS = {"pdf", "doc", "docx"}
MAX_UPLOAD_BYTES = 5 * 1024 * 1024

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("PORTAL_SECRET_KEY") or secrets.token_hex(32),
    MAX_CONTENT_LENGTH=MAX_UPLOAD_BYTES,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # Enable HTTPS before setting this to True in a deployed environment.
    SESSION_COOKIE_SECURE=False,
)
UPLOAD_DIR.mkdir(exist_ok=True)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DATABASE)
    db.execute("PRAGMA foreign_keys = ON")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('student','lecturer')),
            full_name TEXT NOT NULL,
            email TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS grades (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL REFERENCES users(id),
            subject TEXT NOT NULL,
            grade TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS attendance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL REFERENCES users(id),
            subject TEXT NOT NULL,
            attendance_date TEXT NOT NULL,
            status TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS submissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL REFERENCES users(id),
            original_name TEXT NOT NULL,
            stored_name TEXT NOT NULL,
            submitted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL REFERENCES users(id),
            recipient_id INTEGER NOT NULL REFERENCES users(id),
            body TEXT NOT NULL,
            sent_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
    """)

    count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if count == 0:
        db.execute(
            "INSERT INTO users(username,password_hash,role,full_name,email) VALUES(?,?,?,?,?)",
            ("student1", generate_password_hash("Student@123"), "student",
             "Alex Student", "alex.student@example.edu"),
        )
        db.execute(
            "INSERT INTO users(username,password_hash,role,full_name,email) VALUES(?,?,?,?,?)",
            ("lecturer1", generate_password_hash("Lecturer@123"), "lecturer",
             "Dr Lee", "lee@example.edu"),
        )
        student_id = db.execute("SELECT id FROM users WHERE username=?", ("student1",)).fetchone()[0]
        db.executemany(
            "INSERT INTO grades(student_id,subject,grade) VALUES(?,?,?)",
            [(student_id, "Cybersecurity", "A"), (student_id, "Programming", "B+")],
        )
        db.executemany(
            "INSERT INTO attendance(student_id,subject,attendance_date,status) VALUES(?,?,?,?)",
            [(student_id, "Cybersecurity", "2026-11-02", "Present"),
             (student_id, "Programming", "2026-11-04", "Present"),
             (student_id, "Cybersecurity", "2026-11-09", "Absent")],
        )
    db.commit()
    db.close()


def csrf_token():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_urlsafe(32)
    return session["_csrf_token"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def protect_post_requests():
    if request.method == "POST":
        submitted = request.form.get("_csrf_token", "")
        expected = session.get("_csrf_token", "")
        if not expected or not secrets.compare_digest(submitted, expected):
            abort(400, description="Invalid or missing CSRF token.")


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def student_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        user = get_db().execute(
            "SELECT role FROM users WHERE id=?", (session["user_id"],)
        ).fetchone()
        if user is None or user["role"] != "student":
            abort(403)
        return view(*args, **kwargs)
    return wrapped


LAYOUT = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Student Portal Lab</title>
<style>
body{font-family:Arial,sans-serif;max-width:900px;margin:35px auto;padding:0 18px;background:#f5f7fb;color:#202938}
header,section,.card{background:white;padding:18px;margin:14px 0;border-radius:10px;box-shadow:0 1px 5px #ddd}
nav a{margin-right:14px}input,textarea,button{padding:9px;margin:5px 0;max-width:100%}
input,textarea{border:1px solid #bbb;border-radius:5px}button{cursor:pointer}
table{border-collapse:collapse;width:100%}td,th{padding:8px;border-bottom:1px solid #ddd;text-align:left}
.notice{color:#075e36}.error{color:#a21b1b}
</style></head><body>
<header><h1>University Student Portal</h1>
{% if session.get('user_id') %}
<nav><a href="{{url_for('dashboard')}}">Dashboard</a>
<a href="{{url_for('grades')}}">Grades</a><a href="{{url_for('attendance')}}">Attendance</a>
<a href="{{url_for('assignments')}}">Assignments</a><a href="{{url_for('messages')}}">Messages</a>
<a href="{{url_for('profile')}}">My profile</a><a href="{{url_for('logout')}}">Logout</a></nav>
{% endif %}</header>
{% with items=get_flashed_messages(with_categories=true) %}
{% for category,message in items %}<p class="{{'error' if category=='error' else 'notice'}}">{{message}}</p>{% endfor %}
{% endwith %}
<main>{{ content|safe }}</main></body></html>
"""


def page(content, **context):
    return render_template_string(LAYOUT, content=render_template_string(content, **context))


@app.route("/")
def index():
    return redirect(url_for("dashboard") if "user_id" in session else url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = get_db().execute(
            "SELECT id,password_hash FROM users WHERE username=?", (username,)
        ).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            csrf_token()
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.", "error")
    return page("""
    <section><h2>Login</h2><form method="post">
    <input type="hidden" name="_csrf_token" value="{{csrf_token()}}">
    <label>Username<br><input name="username" required></label><br>
    <label>Password<br><input type="password" name="password" required></label><br>
    <button type="submit">Log in</button></form>
    <p>Demo student: student1 / Student@123</p>
    <p>Demo lecturer: lecturer1 / Lecturer@123</p></section>
    """)


@app.route("/logout")
@login_required
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    user = get_db().execute(
        "SELECT username,full_name,role FROM users WHERE id=?", (session["user_id"],)
    ).fetchone()
    return page("""
    <section><h2>Welcome, {{user['full_name']}}</h2>
    <p>Signed in as: {{user['username']}} ({{user['role']}})</p>
    <p>Use the navigation above to access your academic information and portal features.</p>
    </section>""", user=user)


@app.route("/grades")
@student_required
def grades():
    rows = get_db().execute(
        "SELECT subject,grade FROM grades WHERE student_id=? ORDER BY subject",
        (session["user_id"],),
    ).fetchall()
    return page("<section><h2>My grades</h2><table><tr><th>Subject</th><th>Grade</th></tr>"
                "{% for r in rows %}<tr><td>{{r['subject']}}</td><td>{{r['grade']}}</td></tr>{% endfor %}"
                "</table></section>", rows=rows)


@app.route("/attendance")
@student_required
def attendance():
    rows = get_db().execute(
        "SELECT subject,attendance_date,status FROM attendance WHERE student_id=? ORDER BY attendance_date DESC",
        (session["user_id"],),
    ).fetchall()
    return page("<section><h2>My attendance</h2><table><tr><th>Subject</th><th>Date</th><th>Status</th></tr>"
                "{% for r in rows %}<tr><td>{{r['subject']}}</td><td>{{r['attendance_date']}}</td><td>{{r['status']}}</td></tr>{% endfor %}"
                "</table></section>", rows=rows)


@app.route("/assignments", methods=["GET", "POST"])
@student_required
def assignments():
    if request.method == "POST":
        uploaded = request.files.get("assignment")
        if not uploaded or not uploaded.filename:
            flash("Choose a file to upload.", "error")
            return redirect(url_for("assignments"))
        original = secure_filename(uploaded.filename)
        if not original or "." not in original:
            flash("Invalid filename.", "error")
            return redirect(url_for("assignments"))
        extension = original.rsplit(".", 1)[1].lower()
        if extension not in ALLOWED_EXTENSIONS:
            flash("Only PDF, DOC and DOCX files are allowed.", "error")
            return redirect(url_for("assignments"))
        stored = f"{uuid.uuid4().hex}.{extension}"
        uploaded.save(UPLOAD_DIR / stored)
        get_db().execute(
            "INSERT INTO submissions(student_id,original_name,stored_name) VALUES(?,?,?)",
            (session["user_id"], original, stored),
        )
        get_db().commit()
        flash("Assignment uploaded successfully.")
        return redirect(url_for("assignments"))

    rows = get_db().execute(
        "SELECT id,original_name,submitted_at FROM submissions WHERE student_id=? ORDER BY id DESC",
        (session["user_id"],),
    ).fetchall()
    return page("""
    <section><h2>Submit assignment</h2><p>Allowed: PDF, DOC, DOCX. Maximum size: 5 MB.</p>
    <form method="post" enctype="multipart/form-data">
    <input type="hidden" name="_csrf_token" value="{{csrf_token()}}">
    <input type="file" name="assignment" accept=".pdf,.doc,.docx" required>
    <button type="submit">Upload</button></form></section>
    <section><h3>My submissions</h3><ul>{% for r in rows %}
    <li>{{r['original_name']}} — {{r['submitted_at']}}</li>{% else %}<li>No submissions yet.</li>{% endfor %}</ul></section>
    """, rows=rows)


@app.route("/messages", methods=["GET", "POST"])
@login_required
def messages():
    db = get_db()
    if request.method == "POST":
        body = request.form.get("body", "").strip()
        recipient = db.execute(
            "SELECT id FROM users WHERE username=? AND role='lecturer'", ("lecturer1",)
        ).fetchone()
        if not body or len(body) > 2000:
            flash("Message must contain 1–2000 characters.", "error")
        elif recipient is None:
            flash("No lecturer account is available.", "error")
        else:
            db.execute(
                "INSERT INTO messages(sender_id,recipient_id,body) VALUES(?,?,?)",
                (session["user_id"], recipient["id"], body),
            )
            db.commit()
            flash("Message sent.")
        return redirect(url_for("messages"))

    rows = db.execute("""
        SELECT m.body,m.sent_at,s.username AS sender,r.username AS recipient
        FROM messages m JOIN users s ON s.id=m.sender_id
        JOIN users r ON r.id=m.recipient_id
        WHERE m.sender_id=? OR m.recipient_id=?
        ORDER BY m.id DESC
    """, (session["user_id"], session["user_id"])).fetchall()
    return page("""
    <section><h2>Messages</h2><form method="post">
    <input type="hidden" name="_csrf_token" value="{{csrf_token()}}">
    <label>Message to lecturer<br><textarea name="body" maxlength="2000" required></textarea></label><br>
    <button type="submit">Send message</button></form></section>
    <section><h3>Conversation</h3>{% for r in rows %}
    <p><strong>{{r['sender']}} → {{r['recipient']}}</strong> ({{r['sent_at']}})<br>{{r['body']}}</p><hr>
    {% else %}<p>No messages yet.</p>{% endfor %}</section>
    """, rows=rows)


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    db = get_db()
    user_id = session["user_id"]
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip()
        if not full_name or len(full_name) > 100 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            flash("Enter a name (up to 100 characters) and a valid email.", "error")
        else:
            # The user ID comes from the authenticated session, never from the form.
            db.execute(
                "UPDATE users SET full_name=?,email=? WHERE id=?",
                (full_name, email, user_id),
            )
            db.commit()
            flash("Profile updated.")
        return redirect(url_for("profile"))

    user = db.execute(
        "SELECT full_name,email,username,role FROM users WHERE id=?", (user_id,)
    ).fetchone()
    return page("""
    <section><h2>My profile</h2><form method="post">
    <input type="hidden" name="_csrf_token" value="{{csrf_token()}}">
    <label>Full name<br><input name="full_name" maxlength="100" value="{{user['full_name']}}" required></label><br>
    <label>Email<br><input type="email" name="email" value="{{user['email']}}" required></label><br>
    <p>Username: {{user['username']}} | Role: {{user['role']}}</p>
    <button type="submit">Save profile</button></form></section>
    """, user=user)


@app.errorhandler(400)
def bad_request(error):
    return page("<section><h2>Bad request</h2><p>{{message}}</p></section>",
                message=getattr(error, "description", "Bad request")), 400


@app.errorhandler(403)
def forbidden(_error):
    return page("<section><h2>Access denied</h2><p>You are not allowed to access this resource.</p></section>"), 403


@app.errorhandler(413)
def too_large(_error):
    return page("<section><h2>File too large</h2><p>Maximum upload size is 5 MB.</p></section>"), 413


if __name__ == "__main__":
    init_db()
    print("Student Portal running at http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
