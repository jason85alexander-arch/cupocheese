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
# Durable data root: on Render, CUPOCHEESE_DATA_DIR=/var/data (persistent disk).
# Local/dev: unset → project directory (current behavior).
_fallback_dir = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("CUPOCHEESE_DATA_DIR") or _fallback_dir
DATABASE = os.path.join(DATA_DIR, "cupocheese.db")
LINK_HOURS = 1
UPLOAD_FOLDER = os.path.join(DATA_DIR, "uploads")
MAX_AUDIO_BYTES = 15 * 1024 * 1024
MAX_AVATAR_BYTES = 5 * 1024 * 1024
ALLOWED_AUDIO_EXT = {".webm", ".ogg", ".mp4", ".m4a", ".wav", ".mp3"}
ALLOWED_AVATAR_EXT = {".jpg", ".jpeg", ".png", ".webp", ".gif"}
try:
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
except OSError:
    # Disk not attached yet (e.g. /var/data before persistent disk) — use app dir.
    DATA_DIR = _fallback_dir
    DATABASE = os.path.join(DATA_DIR, "cupocheese.db")
    UPLOAD_FOLDER = os.path.join(DATA_DIR, "uploads")
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["MAX_CONTENT_LENGTH"] = max(MAX_AUDIO_BYTES, MAX_AVATAR_BYTES) + 64 * 1024


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def require_user():
    """Return user row or None; clears stale sessions after ephemeral DB wipe."""
    uid = session.get("user_id")
    if not uid:
        return None
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    if not user:
        session.clear()
        return None
    session["username"] = user["username"]
    return user


def _admin_usernames():
    raw = os.environ.get("CUPOCHEESE_ADMINS", "") or ""
    return {p.strip().lower() for p in raw.split(",") if p.strip()}


def is_admin_user(user):
    """True if DB flag set or username listed in CUPOCHEESE_ADMINS."""
    if not user:
        return False
    try:
        if int(user["is_admin"] or 0) == 1:
            return True
    except (KeyError, TypeError, ValueError):
        pass
    uname = (user["username"] or "").strip().lower()
    return bool(uname) and uname in _admin_usernames()


def can_delete_post(viewer, post_user_id):
    if not viewer:
        return False
    if viewer["id"] == post_user_id:
        return True
    return is_admin_user(viewer)


def can_manage_post(viewer, post_user_id):
    """Author or admin may edit text or delete."""
    return can_delete_post(viewer, post_user_id)

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
        # Profile fields (avatar + self-selected top 3 posts)
        cols = {row["name"] for row in db.execute("PRAGMA table_info(users)").fetchall()}
        for col, typ in (
            ("avatar_path", "TEXT"),
            ("top1_post_id", "INTEGER"),
            ("top2_post_id", "INTEGER"),
            ("top3_post_id", "INTEGER"),
            ("is_admin", "INTEGER DEFAULT 0"),
        ):
            if col not in cols:
                db.execute(f"ALTER TABLE users ADD COLUMN {col} {typ}")
        # Promote owner: first user (id=1) or sole remaining user if no admin yet
        admin_n = db.execute(
            "SELECT COUNT(*) AS n FROM users WHERE COALESCE(is_admin, 0) = 1"
        ).fetchone()["n"]
        if admin_n == 0:
            first = db.execute(
                "SELECT id FROM users ORDER BY id ASC LIMIT 1"
            ).fetchone()
            if first:
                db.execute("UPDATE users SET is_admin = 1 WHERE id = ?", (first["id"],))
        db.commit()  # schema ready

@app.route("/")
def index():
    viewer = require_user()
    if not viewer:
        return redirect(url_for("login"))
    db = get_db()
    rows = db.execute("""
        SELECT posts.id, posts.user_id, posts.content, posts.created_at, posts.audio_path,
               COALESCE(users.username, 'unknown') AS username
        FROM posts
        LEFT JOIN users ON posts.user_id = users.id
        ORDER BY posts.created_at DESC
        LIMIT 50
    """).fetchall()
    posts = []
    for row in rows:
        posts.append({
            "id": row["id"],
            "user_id": row["user_id"],
            "content": row["content"],
            "created_at": row["created_at"],
            "audio_path": row["audio_path"],
            "username": row["username"],
            "can_manage": can_manage_post(viewer, row["user_id"]),
        })
    return render_template(
        "feed.html",
        posts=posts,
        username=session.get("username"),
        is_admin=is_admin_user(viewer),
    )

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
            # First account is the site owner / admin
            db.execute(
                "INSERT INTO users (username, email, password_hash, created_at, is_admin) VALUES (?, ?, ?, ?, ?)",
                (username, email, generate_password_hash(password), datetime.utcnow().isoformat(), 1)
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
    if not require_user():
        return redirect(url_for("login"))
    safe = secure_filename(filename)
    if not safe or safe != filename:
        return ("Not found", 404)
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    return send_from_directory(UPLOAD_FOLDER, safe)


@app.errorhandler(413)
def too_large(_err):
    # Avatar edits and clip posts share the same limit; route flash by referrer path.
    path = (request.path or "") + " " + (request.referrer or "")
    if "profile" in path or "avatar" in path:
        flash("That picture is too large (max 5 MB).")
        return redirect(url_for("edit_profile"))
    flash("That clip is too large (max 15 MB). Try a shorter recording.")
    return redirect(url_for("index"))


@app.route("/post", methods=["POST"])
def create_post():
    user = require_user()
    if not user:
        return redirect(url_for("login"))
    content = request.form.get("content", "").strip()
    clip = request.files.get("audio")
    clip_name = None
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    if clip and getattr(clip, "filename", None):
        raw_name = clip.filename or "clip.webm"
        name = secure_filename(raw_name) or "clip.webm"
        ext = os.path.splitext(name)[1].lower()
        if not ext:
            ctype = (clip.mimetype or "").lower()
            if "ogg" in ctype:
                ext = ".ogg"
            elif "mp4" in ctype or "m4a" in ctype or "aac" in ctype:
                ext = ".mp4"
            elif "wav" in ctype:
                ext = ".wav"
            elif "mpeg" in ctype or "mp3" in ctype:
                ext = ".mp3"
            else:
                ext = ".webm"
        if ext in ALLOWED_AUDIO_EXT:
            clip_name = datetime.utcnow().strftime("%Y%m%d%H%M%S") + "_" + secrets.token_hex(8) + ext
            dest = os.path.join(UPLOAD_FOLDER, clip_name)
            try:
                clip.save(dest)
                if os.path.getsize(dest) == 0 or os.path.getsize(dest) > MAX_AUDIO_BYTES:
                    os.remove(dest)
                    clip_name = None
                    flash("Clip could not be saved (empty or too large).")
            except OSError:
                clip_name = None
                flash("Could not store clip on server.")
        else:
            flash("Unsupported audio type. Try recording again.")
    if not content and not clip_name:
        flash("Add some text or a clip before posting.")
        return redirect(url_for("index"))
    db = get_db()
    db.execute(
        "INSERT INTO posts (user_id, content, created_at, audio_path) VALUES (?, ?, ?, ?)",
        (user["id"], content, datetime.utcnow().isoformat(), clip_name),
    )
    db.commit()
    return redirect(url_for("index"))


@app.route("/post/<int:post_id>/delete", methods=["POST"])
def delete_post(post_id):
    viewer = require_user()
    if not viewer:
        return redirect(url_for("login"))
    db = get_db()
    post = db.execute(
        "SELECT id, user_id, audio_path FROM posts WHERE id = ?",
        (post_id,),
    ).fetchone()
    if not post:
        flash("That post is already gone.")
        return redirect(url_for("index"))
    if not can_delete_post(viewer, post["user_id"]):
        flash("You can only delete your own posts.")
        dest = request.referrer if request.referrer else url_for("index")
        return redirect(dest)
    audio = post["audio_path"]
    # Clear any top-3 slots pointing at this post
    db.execute(
        "UPDATE users SET top1_post_id = NULL WHERE top1_post_id = ?",
        (post_id,),
    )
    db.execute(
        "UPDATE users SET top2_post_id = NULL WHERE top2_post_id = ?",
        (post_id,),
    )
    db.execute(
        "UPDATE users SET top3_post_id = NULL WHERE top3_post_id = ?",
        (post_id,),
    )
    db.execute("DELETE FROM posts WHERE id = ?", (post_id,))
    db.commit()
    if audio:
        path = os.path.join(UPLOAD_FOLDER, audio)
        if os.path.isfile(path):
            try:
                os.remove(path)
            except OSError:
                pass
    flash("Post deleted.")
    dest = request.referrer if request.referrer else url_for("index")
    # Avoid redirect loops back to the deleted post URL if any
    if dest and f"/post/{post_id}" in dest:
        dest = url_for("index")
    return redirect(dest)


@app.route("/post/<int:post_id>/edit", methods=["GET", "POST"])
def edit_post(post_id):
    viewer = require_user()
    if not viewer:
        return redirect(url_for("login"))
    db = get_db()
    post = db.execute(
        "SELECT id, user_id, content, audio_path, created_at FROM posts WHERE id = ?",
        (post_id,),
    ).fetchone()
    if not post:
        flash("That post is gone.")
        return redirect(url_for("index"))
    if not can_manage_post(viewer, post["user_id"]):
        flash("You can only edit your own posts.")
        return redirect(url_for("index"))

    if request.method == "POST":
        content = request.form.get("content", "").strip()
        audio = post["audio_path"]
        if not content and not audio:
            flash("Add some text or keep a clip — empty posts aren't allowed.")
            return render_template(
                "edit_post.html",
                post=post,
                content="",
                username=session.get("username"),
            )
        db.execute(
            "UPDATE posts SET content = ? WHERE id = ?",
            (content, post_id),
        )
        db.commit()
        flash("Post updated.")
        dest = request.form.get("next") or request.referrer or url_for("index")
        if dest and f"/post/{post_id}/edit" in dest:
            dest = url_for("index")
        return redirect(dest)

    return render_template(
        "edit_post.html",
        post=post,
        content=post["content"] or "",
        username=session.get("username"),
    )


def _parse_optional_post_id(raw):
    raw = (raw or "").strip()
    if not raw:
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _owned_post_id(db, user_id, post_id):
    if post_id is None:
        return None
    row = db.execute(
        "SELECT id FROM posts WHERE id = ? AND user_id = ?",
        (post_id, user_id),
    ).fetchone()
    return row["id"] if row else None


def _load_top_posts(db, user_row):
    """Return ordered list of existing top posts (skip deleted)."""
    tops = []
    for key in ("top1_post_id", "top2_post_id", "top3_post_id"):
        pid = user_row[key] if key in user_row.keys() else None
        if not pid:
            continue
        post = db.execute(
            "SELECT id, content, created_at, audio_path FROM posts WHERE id = ? AND user_id = ?",
            (pid, user_row["id"]),
        ).fetchone()
        if post:
            tops.append(post)
    return tops


@app.route("/me")
def me():
    user = require_user()
    if not user:
        return redirect(url_for("login"))
    return redirect(url_for("user_profile", username=user["username"]))


@app.route("/u/<username>")
def user_profile(username):
    viewer = require_user()
    if not viewer:
        return redirect(url_for("login"))
    db = get_db()
    profile = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if not profile:
        flash("No member by that name.")
        return redirect(url_for("index"))
    tops_raw = _load_top_posts(db, profile)
    is_owner = viewer["id"] == profile["id"]
    viewer_admin = is_admin_user(viewer)
    tops = []
    for post in tops_raw:
        tops.append({
            "id": post["id"],
            "content": post["content"],
            "created_at": post["created_at"],
            "audio_path": post["audio_path"],
            "can_manage": is_owner or viewer_admin,
        })
    return render_template(
        "profile.html",
        profile=profile,
        tops=tops,
        is_owner=is_owner,
        username=session.get("username"),
        is_admin=viewer_admin,
    )


@app.route("/people")
def people():
    viewer = require_user()
    if not viewer:
        return redirect(url_for("login"))
    db = get_db()
    rows = db.execute(
        """
        SELECT id, username, avatar_path, created_at
        FROM users
        ORDER BY lower(username) ASC
        """
    ).fetchall()
    members = []
    for row in rows:
        members.append({
            "id": row["id"],
            "username": row["username"],
            "avatar_path": row["avatar_path"],
            "created_at": row["created_at"],
            "is_you": row["id"] == viewer["id"],
        })
    return render_template(
        "people.html",
        members=members,
        username=session.get("username"),
    )


@app.route("/avatar/<filename>")
def serve_avatar(filename):
    if not require_user():
        return redirect(url_for("login"))
    safe = secure_filename(filename)
    if not safe or safe != filename:
        return ("Not found", 404)
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    return send_from_directory(UPLOAD_FOLDER, safe)


@app.route("/profile/edit", methods=["GET", "POST"])
def edit_profile():
    user = require_user()
    if not user:
        return redirect(url_for("login"))
    db = get_db()
    if request.method == "POST":
        # Refresh user row for latest avatar / tops
        user = db.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
        avatar = request.files.get("avatar")
        new_avatar = None
        if avatar and getattr(avatar, "filename", None):
            raw_name = avatar.filename or "avatar.jpg"
            name = secure_filename(raw_name) or "avatar.jpg"
            ext = os.path.splitext(name)[1].lower()
            if not ext:
                ctype = (avatar.mimetype or "").lower()
                if "png" in ctype:
                    ext = ".png"
                elif "webp" in ctype:
                    ext = ".webp"
                elif "gif" in ctype:
                    ext = ".gif"
                else:
                    ext = ".jpg"
            if ext not in ALLOWED_AVATAR_EXT:
                flash("Avatar must be jpeg, png, webp, or gif.")
                return redirect(url_for("edit_profile"))
            os.makedirs(UPLOAD_FOLDER, exist_ok=True)
            new_avatar = (
                datetime.utcnow().strftime("%Y%m%d%H%M%S")
                + "_av_"
                + secrets.token_hex(8)
                + ext
            )
            dest = os.path.join(UPLOAD_FOLDER, new_avatar)
            try:
                avatar.save(dest)
                size = os.path.getsize(dest)
                if size == 0 or size > MAX_AVATAR_BYTES:
                    os.remove(dest)
                    flash("Avatar could not be saved (empty or over 5 MB).")
                    return redirect(url_for("edit_profile"))
            except OSError:
                flash("Could not store avatar on server.")
                return redirect(url_for("edit_profile"))

        # Ordered top 3 — ownership validated; blanks clear a slot
        t1 = _owned_post_id(db, user["id"], _parse_optional_post_id(request.form.get("top1")))
        t2 = _owned_post_id(db, user["id"], _parse_optional_post_id(request.form.get("top2")))
        t3 = _owned_post_id(db, user["id"], _parse_optional_post_id(request.form.get("top3")))
        # Deduplicate while preserving order (first pick wins)
        seen = set()
        ordered = []
        for pid in (t1, t2, t3):
            if pid is None:
                ordered.append(None)
            elif pid in seen:
                ordered.append(None)
            else:
                seen.add(pid)
                ordered.append(pid)
        t1, t2, t3 = ordered

        if new_avatar:
            # Drop old avatar file if present
            old = user["avatar_path"] if "avatar_path" in user.keys() else None
            if old:
                old_path = os.path.join(UPLOAD_FOLDER, old)
                if os.path.isfile(old_path):
                    try:
                        os.remove(old_path)
                    except OSError:
                        pass
            db.execute(
                "UPDATE users SET avatar_path = ?, top1_post_id = ?, top2_post_id = ?, top3_post_id = ? WHERE id = ?",
                (new_avatar, t1, t2, t3, user["id"]),
            )
        else:
            db.execute(
                "UPDATE users SET top1_post_id = ?, top2_post_id = ?, top3_post_id = ? WHERE id = ?",
                (t1, t2, t3, user["id"]),
            )
        db.commit()
        flash("Profile updated — looking sharp (and fragrant).")
        return redirect(url_for("user_profile", username=user["username"]))

    user = db.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
    my_posts = db.execute(
        "SELECT id, content, created_at, audio_path FROM posts WHERE user_id = ? ORDER BY created_at DESC LIMIT 100",
        (user["id"],),
    ).fetchall()
    return render_template(
        "profile_edit.html",
        profile=user,
        my_posts=my_posts,
        username=session.get("username"),
    )


init_db()
account_flow.register_routes(app, get_db)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=os.environ.get("FLASK_DEBUG") == "1")