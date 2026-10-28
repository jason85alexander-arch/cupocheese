import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get("CUPOCHEESE_SECRET", "cupocheese-dev-secret-change-me")
DATABASE = "cupocheese.db"

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
                password_hash TEXT NOT NULL,
                created_at TEXT
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        """)
        db.commit()

@app.route("/")
def index():
    if "user_id" not in session:
        return redirect(url_for("login"))
    db = get_db()
    posts = db.execute("""
        SELECT posts.content, posts.created_at, users.username
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
        password = request.form["password"]
        invite = request.form.get("invite", "").strip()
        if invite != INVITE_CODE:
            flash("Signups are closed. You need an invite.")
            return redirect(url_for("register"))
        if not username or not password:
            flash("Username and password required")
            return redirect(url_for("register"))
        db = get_db()
        # First account only: if any users exist, block further signups even with the invite
        existing = db.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
        if existing >= 1:
            flash("Signups are closed. Owner account already exists.")
            return redirect(url_for("login"))
        try:
            db.execute(
                "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                (username, generate_password_hash(password), datetime.utcnow().isoformat())
            )
            db.commit()
            flash("Account created. Pour a cup and dig in.")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
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

@app.route("/post", methods=["POST"])
def create_post():
    if "user_id" not in session:
        return redirect(url_for("login"))
    content = request.form.get("content", "").strip()
    if content:
        db = get_db()
        db.execute(
            "INSERT INTO posts (user_id, content, created_at) VALUES (?, ?, ?)",
            (session["user_id"], content, datetime.utcnow().isoformat())
        )
        db.commit()
    return redirect(url_for("index"))

init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=os.environ.get("FLASK_DEBUG") == "1")
