import os
import secrets
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
from datetime import datetime, timedelta
import account_flow

app = Flask(__name__)
app.secret_key = os.environ.get("CUPOCHEESE_SECRET", "cupocheese-dev-secret-change-me")
DATABASE = "cupocheese.db"
LINK_HOURS = 1
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
MAX_AUDIO_BYTES = 5 * 1024 * 1024
ALLOWED_AUDIO_EXT = {".webm", ".ogg", ".mp4", ".m4a", ".wav", ".mp3"}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["MAX_CONTENT_LENGTH"] = MAX_AUDIO_BYTES + 64 * 1024


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT
            )
        """)
        cols = {row["name"] for row in db.execute("PRAGMA table_info(users)").fetchall()}
        if "email" not in cols:
            db.execute("ALTER TABLE users ADD COLUMN email TEXT")
        db.execute("""
            CREATE TABLE IF NOT EXISTS posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT,
                audio_path TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        """)
        post_cols = {row["name"] for row in db.execute("PRAGMA table_info(posts)").fetchall()}
        if "audio_path" not in post_cols:
            db.execute("ALTER TABLE posts ADD COLUMN audio_path TEXT")
        db.commit()  # schema ready

@app.route("/")
def index():
    if "user_id" not in session:
        return redirect(url_for("login"))
    db = get_db()
    posts = db.execute("""
        SELECT posts.id, posts.content, posts.created_at, posts.audio_path, users.username
        FROM posts
        JOIN users ON posts.user_id = users.id
        ORDER BY posts.created_at DESC
        LIMIT 50
    """).fetchall()
    return render_template("feed.html", posts=posts, username=session.get("username"))

# Only you can create an account for now. Change this env var to rotate the invite.
INVITE_CODE = os.environ.get("CUPOCHEESE_INVITE", "owner-only-cupocheese")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form["password"]
        password_confirm = request.form.get("password_confirm", "")
        invite = request.form.get("invite", "").strip()
        if invite != INVITE_CODE:
            flash("Signups are closed. You need an invite.")
            return redirect(url_for("register"))
        if not username or not email or not password:
            flash("Username, email, and password required")
            return redirect(url_for("register"))
        if "@" not in email or "." not in email.split("@")[-1]:
            flash("Enter a valid email address")
            return redirect(url_for("register"))
        if password != password_confirm:
            flash("Passwords must match")
            return redirect(url_for("register"))
        db = get_db()
        # First account only: if any users exist, block further signups even with the invite
        existing = db.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
        if existing >= 1:
            flash("Signups are closed. Owner account already exists.")
            return redirect(url_for("login"))
        try:
            db.execute(
                "INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (username, email, generate_password_hash(password), datetime.utcnow().isoformat())
            )
            db.commit()
            flash("Account Created! Hike a leg and come on in!")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError as e:
            if "email" in str(e).lower():
                flash("Email already registered")
            else:
                flash("Username already taken")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("index"))
        flash("Invalid username or password")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/clip/<filename>")
def serve_clip(filename):
    if "user_id" not in session:
        return redirect(url_for("login"))
    safe = secure_filename(filename)
    if not safe or safe != filename:
        return ("Not found", 404)
    return send_from_directory(UPLOAD_FOLDER, safe)


@app.route("/post", methods=["POST"])
def create_post():
    if "user_id" not in session:
        return redirect(url_for("login"))
    content = request.form.get("content", "").strip()
    clip = request.files.get("audio")
    clip_name = None
    if clip and clip.filename:
        name = secure_filename(clip.filename)
        ext = os.path.splitext(name)[1].lower() or ".webm"
        if ext in ALLOWED_AUDIO_EXT:
            clip_name = datetime.utcnow().strftime("%Y%m%d%H%M%S") + "_" + secrets.token_hex(8) + ext
            dest = os.path.join(UPLOAD_FOLDER, clip_name)
            clip.save(dest)
            if os.path.getsize(dest) > MAX_AUDIO_BYTES:
                os.remove(dest)
                clip_name = None
    if not content and not clip_name:
        flash("Add some text or a clip before posting.")
        return redirect(url_for("index"))
    db = get_db()
    db.execute(
        "INSERT INTO posts (user_id, content, created_at, audio_path) VALUES (?, ?, ?, ?)",
        (session["user_id"], content, datetime.utcnow().isoformat(), clip_name),
    )
    db.commit()
    return redirect(url_for("index"))

init_db()
account_flow.register_routes(app, get_db)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=os.environ.get("FLASK_DEBUG") == "1")