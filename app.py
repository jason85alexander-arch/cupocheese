import os
import secrets
import fcntl
import hashlib
import threading
import time
from flask import Flask, has_app_context, render_template, request, redirect, url_for, session, flash, send_from_directory, g, jsonify, get_template_attribute, abort
from markupsafe import Markup, escape
import json
import re
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
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
# 30-second clip cap. Server allows a little slack over the client's auto-stop.
MAX_CLIP_SECONDS = 30
CLIP_SECONDS_SLACK = 1.0
# When duration can't be read (MediaRecorder webm usually has no duration header),
# fall back to a byte ceiling sized for ~30s at generous bitrates (opus ~32-128 kbps, AAC ~128-256 kbps).
UNKNOWN_DURATION_MAX_BYTES = int(1.5 * 1024 * 1024)
CLIP_TOO_LONG_MSG = "Whoa, that's a long one! Keep it under 30 seconds."
MAX_AVATAR_BYTES = 5 * 1024 * 1024
POST_MAX_CHARS = 140
MSG_TOO_LONG = f"Keep it under {POST_MAX_CHARS} characters — let the fart do the talking."
MSG_NO_TOOT = "No toot, no post! Record a clip first."
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


class _RequestConnection(sqlite3.Connection):
    """The one shared connection for a request/app context.

    Legacy helpers call db.close() on what used to be a private connection; that is now a
    no-op so they can't close the request's connection under the caller. Teardown really closes it.
    """

    def close(self):
        pass

    def really_close(self):
        sqlite3.Connection.close(self)


def _connect(factory=sqlite3.Connection):
    # timeout + busy_timeout: wait up to 5 s for another worker's write lock instead of erroring.
    conn = sqlite3.connect(DATABASE, timeout=5.0, factory=factory)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn


def get_db():
    """One connection per request (reused for every query, closed on teardown).

    Outside an app/request context (startup, scripts) a fresh private connection is returned.
    """
    if has_app_context():
        conn = g.get("_db")
        if conn is None:
            conn = g._db = _connect(_RequestConnection)
        return conn
    return _connect()


@app.teardown_appcontext
def _close_db(exc):
    conn = g.pop("_db", None)
    if conn is not None:
        try:
            if conn.in_transaction:
                conn.rollback()
        finally:
            conn.really_close()


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


def _admin_name_set():
    """Lowercased usernames of all admins (DB flag + CUPOCHEESE_ADMINS), cached per request."""
    cached = getattr(g, "_admin_names", None)
    if cached is not None:
        return cached
    names = set(_admin_usernames())
    try:
        db = get_db()
        for r in db.execute("SELECT username FROM users WHERE COALESCE(is_admin, 0) = 1"):
            if r["username"]:
                names.add(r["username"].strip().lower())
        db.close()
    except sqlite3.Error:
        pass
    g._admin_names = names
    return names


@app.context_processor
def _inject_admin_badge():
    def admin_badge(username):
        uname = (username or "").strip().lower()
        if uname and uname in _admin_name_set():
            return Markup(' <span class="admin-badge" title="Admin" aria-label="Admin">💩</span>')
        return ""
    def member_no(username):
        """Admin-only join-order badge like '#3'. Empty for non-admins."""
        if not _viewer_is_admin():
            return ""
        uname = (username or "").strip().lower()
        if not uname:
            return ""
        nums = getattr(g, "_member_nos", None)
        if nums is None:
            nums = {}
            try:
                db = get_db()
                for r in db.execute("SELECT username, member_no FROM users WHERE member_no IS NOT NULL"):
                    nums[(r["username"] or "").strip().lower()] = r["member_no"]
                db.close()
            except sqlite3.Error:
                pass
            g._member_nos = nums
        n = nums.get(uname)
        if not n:
            return ""
        return Markup(f' <span class="member-no" title="Member #{n} (join order, admins only)">#{n}</span>')
    def real_name(username):
        """Admin-only real name ('First Last'). Empty string for non-admins, always."""
        if not _viewer_is_admin():
            return ""
        uname = (username or "").strip().lower()
        if not uname:
            return ""
        names = getattr(g, "_real_names", None)
        if names is None:
            names = {}
            try:
                db = get_db()
                for r in db.execute("SELECT username, first_name, last_name FROM users"):
                    full = " ".join(p for p in ((r["first_name"] or "").strip(), (r["last_name"] or "").strip()) if p)
                    if full:
                        names[(r["username"] or "").strip().lower()] = full
                db.close()
            except sqlite3.Error:
                pass
            g._real_names = names
        return names.get(uname, "")
    return {"admin_badge": admin_badge, "viewer_is_admin": _viewer_is_admin, "member_no": member_no,
            "real_name": real_name, "name_max": NAME_MAX_CHARS, "name_note": NAME_PRIVACY_NOTE}


# ---- Real names (first/last): required, but only admins ever see them ----
NAME_MAX_CHARS = 40
NAME_PRIVACY_NOTE = "🔒 Only admins can see your real name. Everyone else just sees your username."


def clean_name(raw):
    """Trim, collapse inner whitespace, cap length. Returns '' when blank."""
    return " ".join((raw or "").split())[:NAME_MAX_CHARS]


def has_real_name(user):
    try:
        return bool((user["first_name"] or "").strip()) and bool((user["last_name"] or "").strip())
    except (KeyError, IndexError, TypeError):
        return False


# ---- Usernames: shared rules for signup + rename ----
USERNAME_MIN, USERNAME_MAX = 2, 30
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.\-]+$")
USERNAME_CHANGE_DAYS = 90


def username_error(db, name, exclude_user_id=None):
    """Return a friendly error message, or None if `name` (already trimmed) is usable."""
    if not name:
        return "Pick a username."
    if len(name) < USERNAME_MIN or len(name) > USERNAME_MAX:
        return f"Usernames are {USERNAME_MIN}–{USERNAME_MAX} characters."
    if not USERNAME_RE.match(name):
        return "Usernames can use letters, numbers, underscores, dots, and dashes (no spaces)."
    row = db.execute("SELECT id FROM users WHERE lower(username) = lower(?)", (name,)).fetchone()
    if row and row["id"] != exclude_user_id:
        return "Username already taken"
    return None


def username_unlock_at(user):
    """UTC datetime when this member may rename again, or None if they can now."""
    try:
        raw = user["username_changed_at"]
    except (KeyError, IndexError):
        raw = None
    if not raw:
        return None
    try:
        last = datetime.fromisoformat(raw)
    except ValueError:
        return None
    unlock = last + timedelta(days=USERNAME_CHANGE_DAYS)
    return unlock if _now_utc() < unlock else None


@app.template_filter("ct_date")
def ct_date(value):
    """Stored UTC -> Central calendar date, e.g. 'Thu, Jan 28, 2027'."""
    d = to_central(value)
    if d is None:
        return ""
    return f"{d.strftime('%a, %b')} {d.day}, {d.year}"


def rename_user(db, user, new_name):
    """Rename in one transaction. Everything else references users.id, so only users changes
    (plus a history row for old-URL redirects). Caller commits."""
    now = _now_utc().isoformat()
    db.execute("INSERT INTO username_history (user_id, old_username, changed_at) VALUES (?, ?, ?)",
               (user["id"], user["username"], now))
    db.execute("UPDATE users SET username = ?, username_changed_at = ? WHERE id = ?", (new_name, now, user["id"]))
    # Env-listed admins (CUPOCHEESE_ADMINS) are matched by name; keep their admin via the DB flag.
    if (user["username"] or "").strip().lower() in _admin_usernames():
        db.execute("UPDATE users SET is_admin = 1 WHERE id = ?", (user["id"],))


# Signed-in members with no first/last name are sent to /add-name first.
NAME_GATE_EXEMPT = {"add_name", "logout", "static", "healthz", "service_worker", "pwa_manifest", "offline"}


@app.before_request
def _require_real_name():
    if request.endpoint in NAME_GATE_EXEMPT or request.endpoint is None:
        return None
    uid = session.get("user_id")
    if not uid:
        return None
    try:
        row = get_db().execute("SELECT first_name, last_name FROM users WHERE id = ?", (uid,)).fetchone()
    except sqlite3.Error:
        return None
    if row is None or has_real_name(row):
        return None
    target = url_for("add_name")
    if _wants_json():
        return jsonify({"ok": False, "error": "name required", "redirect": target}), 403
    return redirect(target)


def _viewer_is_admin():
    """Is the signed-in viewer an admin? (fresh from DB each request)"""
    cached = getattr(g, "_viewer_admin", None)
    if cached is not None:
        return cached
    val = False
    uid = session.get("user_id")
    if uid:
        try:
            db = get_db()
            row = db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
            db.close()
            val = is_admin_user(row)
        except sqlite3.Error:
            val = False
    g._viewer_admin = val
    return val


def owner_user_id(db):
    """The site owner = the first account ever created (lowest id). Can't be demoted."""
    row = db.execute("SELECT id FROM users ORDER BY id ASC LIMIT 1").fetchone()
    return row["id"] if row else None


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
    """Create/migrate the schema. Safe with several gunicorn workers starting at once:
    an exclusive file lock serializes migrations (gunicorn.conf.py also preloads, so it
    normally runs once in the master before forking)."""
    lock = open(os.path.join(DATA_DIR, ".migrate.lock"), "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        db = _connect()
        try:
            # WAL: readers never block the writer (persistent setting stored in the DB file).
            db.execute("PRAGMA journal_mode=WAL")
            _init_db_locked(db)
        finally:
            db.close()
    finally:
        fcntl.flock(lock, fcntl.LOCK_UN)
        lock.close()


def _init_db_locked(db):
    with db:
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
        db.execute("CREATE INDEX IF NOT EXISTS idx_posts_created ON posts (created_at)")
        post_cols = {row["name"] for row in db.execute("PRAGMA table_info(posts)").fetchall()}
        if "audio_path" not in post_cols:
            db.execute("ALTER TABLE posts ADD COLUMN audio_path TEXT")
        if "pinned_at" not in post_cols:
            db.execute("ALTER TABLE posts ADD COLUMN pinned_at TEXT")
        if "self_reacted_at" not in post_cols:
            db.execute("ALTER TABLE posts ADD COLUMN self_reacted_at TEXT")
        db.execute("CREATE INDEX IF NOT EXISTS idx_posts_pinned ON posts (pinned_at)")
        # Profile fields (avatar + self-selected top 3 posts)
        cols = {row["name"] for row in db.execute("PRAGMA table_info(users)").fetchall()}
        for col, typ in (
            ("avatar_path", "TEXT"),
            ("top1_post_id", "INTEGER"),
            ("top2_post_id", "INTEGER"),
            ("top3_post_id", "INTEGER"),
            ("is_admin", "INTEGER DEFAULT 0"),
            ("member_no", "INTEGER"),
            ("back_draft_seen_at", "TEXT"),
            ("first_name", "TEXT"),
            ("last_name", "TEXT"),
            ("username_changed_at", "TEXT"),
        ):
            if col not in cols:
                db.execute(f"ALTER TABLE users ADD COLUMN {col} {typ}")
        # Unread Back Draft badge: start everyone at "now" so nobody sees a backlog.
        db.execute(
            "UPDATE users SET back_draft_seen_at = ? WHERE back_draft_seen_at IS NULL",
            (datetime.utcnow().isoformat(),),
        )
        # Join-order member numbers (#1 = first account). Assigned once, never renumbered.
        for r in db.execute("SELECT id FROM users WHERE member_no IS NULL ORDER BY id").fetchall():
            nxt = db.execute("SELECT COALESCE(MAX(member_no), 0) + 1 FROM users").fetchone()[0]
            db.execute("UPDATE users SET member_no = ? WHERE id = ?", (nxt, r["id"]))
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
        # Old usernames (so /u/<old name> links redirect after a rename).
        db.execute("""
            CREATE TABLE IF NOT EXISTS username_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                old_username TEXT NOT NULL,
                changed_at TEXT
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_username_history_old ON username_history (lower(old_username))")
        # Cheese Boards: members post on each other's profile pages (no DMs).
        db.execute("""
            CREATE TABLE IF NOT EXISTS board_posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                board_user_id INTEGER NOT NULL,
                author_id INTEGER NOT NULL,
                body TEXT NOT NULL DEFAULT '',
                audio_path TEXT,
                created_at TEXT,
                FOREIGN KEY (board_user_id) REFERENCES users (id),
                FOREIGN KEY (author_id) REFERENCES users (id)
            )
        """)
        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_board_posts_board ON board_posts (board_user_id, created_at)"
        )
        db.execute("CREATE INDEX IF NOT EXISTS idx_board_posts_created ON board_posts (created_at)")
        bp_cols = {row["name"] for row in db.execute("PRAGMA table_info(board_posts)").fetchall()}
        if "self_reacted_at" not in bp_cols:
            # Permanent "geek" mark: set on the author's first reaction to their own post, never cleared.
            db.execute("ALTER TABLE board_posts ADD COLUMN self_reacted_at TEXT")
        # Emoji reactions (no comments) on feed posts and Cheese Board posts.
        db.execute("""
            CREATE TABLE IF NOT EXISTS reactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_type TEXT NOT NULL,
                target_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                emoji TEXT NOT NULL,
                created_at TEXT,
                UNIQUE (target_type, target_id, user_id, emoji),
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        """)
        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_reactions_target ON reactions (target_type, target_id)"
        )
        # In-app notifications (no email/push).
        db.execute("""
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                actor_id INTEGER,
                kind TEXT NOT NULL,
                target_type TEXT,
                target_id INTEGER,
                emoji TEXT,
                created_at TEXT,
                read_at TEXT
            )
        """)
        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications (user_id, read_at)"
        )
        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_notifications_target ON notifications (target_type, target_id)"
        )
        # Cheek Squeak O' the Week: one row per completed week that had a winner.
        db.execute("""
            CREATE TABLE IF NOT EXISTS awards (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                week_start TEXT NOT NULL UNIQUE,
                post_id INTEGER,
                user_id INTEGER,
                reaction_count INTEGER,
                created_at TEXT
            )
        """)
        aw_cols = {row["name"] for row in db.execute("PRAGMA table_info(awards)").fetchall()}
        if "target_type" not in aw_cols:
            # Existing awards were all feed posts; keep them exactly as stored.
            db.execute("ALTER TABLE awards ADD COLUMN target_type TEXT NOT NULL DEFAULT 'post'")
        # Admin-issued, single-use invites.
        db.execute("""
            CREATE TABLE IF NOT EXISTS invites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code TEXT UNIQUE NOT NULL,
                email TEXT,
                created_by INTEGER,
                created_at TEXT,
                used_by INTEGER,
                used_at TEXT,
                revoked_by INTEGER,
                revoked_at TEXT
            )
        """)
        db.commit()  # schema ready

REACTION_EMOJIS = ["😷", "☠️", "🦨", "🎺", "🚀", "😂", "👏", "🏆", "🫡", "🤌", "🐐", "👀", "wet_one"]
# Custom image reactions: stored key -> (label, static image path). Rendered as <img> via rx_glyph.
CUSTOM_REACTIONS = {"wet_one": ("Wet one", "rx/wet_one-v1-64.png")}
REACTION_TARGETS = {"post": "posts", "board": "board_posts"}


def _norm_emoji(e):
    return (e or "").replace("\ufe0f", "").strip()


_REACTION_LOOKUP = {_norm_emoji(e): e for e in REACTION_EMOJIS}


def load_reactions(db, kind, ids, viewer_id):
    """Batch-load reactions for many targets. Returns {target_id: [ {emoji,count,mine,who}, ...11 ]}."""
    ids = [int(i) for i in ids if i is not None]
    raw = {i: {} for i in ids}
    if ids:
        marks = ",".join("?" * len(ids))
        rows = db.execute(
            f"""
            SELECT r.target_id, r.emoji, COUNT(*) AS n,
                   MAX(CASE WHEN r.user_id = ? THEN 1 ELSE 0 END) AS mine,
                   GROUP_CONCAT(COALESCE(u.username, '?'), ', ') AS who
            FROM reactions r LEFT JOIN users u ON u.id = r.user_id
            WHERE r.target_type = ? AND r.target_id IN ({marks})
            GROUP BY r.target_id, r.emoji
            """,
            [viewer_id, kind] + ids,
        ).fetchall()
        for r in rows:
            raw.setdefault(r["target_id"], {})[r["emoji"]] = r
    out = {}
    for tid, by_emoji in raw.items():
        lst = []
        for e in REACTION_EMOJIS:
            r = by_emoji.get(e)
            lst.append({
                "emoji": e,
                "count": r["n"] if r else 0,
                "mine": bool(r["mine"]) if r else False,
                "who": r["who"] if r else "",
            })
        out[tid] = lst
    return out


def delete_reactions(db, kind, target_id):
    db.execute("DELETE FROM reactions WHERE target_type = ? AND target_id = ?", (kind, target_id))
    delete_target_notifications(db, kind, target_id)


# ---------------- Notifications ----------------
NOTIFY_KEEP = 100


def notify(db, recipient_id, actor_id, kind, target_type=None, target_id=None, emoji=None):
    """Create an in-app notification. Never notifies yourself."""
    if recipient_id is None:
        return
    if actor_id is not None and int(actor_id) == int(recipient_id):
        return
    db.execute(
        "INSERT INTO notifications (user_id, actor_id, kind, target_type, target_id, emoji, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (recipient_id, actor_id, kind, target_type, target_id, emoji, _now_utc().isoformat()),
    )
    prune_notifications(db, recipient_id)


def prune_notifications(db, user_id, keep=NOTIFY_KEEP):
    db.execute(
        "DELETE FROM notifications WHERE user_id = ? AND id NOT IN "
        "(SELECT id FROM notifications WHERE user_id = ? ORDER BY created_at DESC, id DESC LIMIT ?)",
        (user_id, user_id, keep),
    )


def delete_target_notifications(db, target_type, target_id):
    db.execute(
        "DELETE FROM notifications WHERE target_type = ? AND target_id = ?",
        (target_type, target_id),
    )


def unread_notification_count(user_id):
    if not user_id:
        return 0
    if "_unread_n" in g:
        return g._unread_n
    try:
        n = get_db().execute(
            "SELECT COUNT(*) FROM notifications WHERE user_id = ? AND read_at IS NULL", (user_id,)
        ).fetchone()[0]
    except sqlite3.Error:
        n = 0
    g._unread_n = n
    return n


def unread_back_draft_count(user_id):
    """New Back Draft posts by others since the viewer last opened the feed (one indexed COUNT)."""
    if not user_id:
        return 0
    if "_unread_bd" in g:
        return g._unread_bd
    try:
        n = get_db().execute(
            """WITH seen AS (SELECT COALESCE(back_draft_seen_at, created_at, '') AS t FROM users WHERE id = ?)
               SELECT (SELECT COUNT(*) FROM posts
                        WHERE created_at > (SELECT t FROM seen) AND user_id != ?)
                    + (SELECT COUNT(*) FROM board_posts
                        WHERE created_at > (SELECT t FROM seen) AND author_id != ?)""",
            (user_id, user_id, user_id),
        ).fetchone()[0] or 0
    except sqlite3.Error:
        n = 0
    g._unread_bd = n
    return n


@app.context_processor
def _inject_notifications():
    uid = session.get("user_id")
    return {
        "unread_notifications": unread_notification_count(uid),
        "unread_back_draft": unread_back_draft_count(uid),
    }


# ---------------- Cheek Squeak O' the Week ----------------
CENTRAL = ZoneInfo("America/Chicago")


def _now_utc():
    """Naive UTC now (matches stored created_at). Tests may monkeypatch this."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def week_bounds(now_utc=None, weeks_back=0):
    """Return (week_start_date_ct, start_utc_naive, end_utc_naive) for a Mon-Sun Central week.

    weeks_back=0 is the current (in-progress) week, 1 is the most recent completed week.
    """
    now_utc = now_utc or _now_utc()
    now_ct = to_central(now_utc)
    monday = (now_ct - timedelta(days=now_ct.weekday())).date() - timedelta(weeks=weeks_back)
    start_ct = datetime(monday.year, monday.month, monday.day, tzinfo=CENTRAL)
    nxt = monday + timedelta(days=7)
    end_ct = datetime(nxt.year, nxt.month, nxt.day, tzinfo=CENTRAL)
    to_utc = lambda d: d.astimezone(timezone.utc).replace(tzinfo=None)
    return monday, to_utc(start_ct), to_utc(end_ct)


def top_post_between(db, start_utc, end_utc):
    """Back Draft toot (feed post or Cheese Board post) created in [start, end) with most reactions
    from people other than its author; ties -> most distinct (non-author) reactors, then earliest.
    Self-reactions never count. Returns row with kind ('post'|'board'), id, user_id (author), n, d."""
    s, e = start_utc.isoformat(), end_utc.isoformat()
    return db.execute(
        """
        SELECT * FROM (
            SELECT 'post' AS kind, p.id, p.user_id, p.created_at, COUNT(r.id) AS n, COUNT(DISTINCT r.user_id) AS d
            FROM posts p
            JOIN reactions r ON r.target_type = 'post' AND r.target_id = p.id AND r.user_id != p.user_id
            WHERE p.created_at >= ? AND p.created_at < ?
            GROUP BY p.id
            UNION ALL
            SELECT 'board' AS kind, b.id, b.author_id AS user_id, b.created_at, COUNT(r.id) AS n, COUNT(DISTINCT r.user_id) AS d
            FROM board_posts b
            JOIN reactions r ON r.target_type = 'board' AND r.target_id = b.id AND r.user_id != b.author_id
            WHERE b.created_at >= ? AND b.created_at < ?
            GROUP BY b.id
        )
        WHERE n >= 1
        ORDER BY n DESC, d DESC, created_at ASC, kind DESC, id ASC
        LIMIT 1
        """,
        (s, e, s, e),
    ).fetchone()


# Per-process cache of the weekly award check. A decided award never changes, so it is cached
# for good; "no winner yet" is cached until a new reaction appears (or a 5-minute TTL).
# Cross-worker safety comes from awards.week_start UNIQUE + INSERT OR IGNORE.
_AWARD_CACHE = {}
_AWARD_LOCK = threading.Lock()
AWARD_MISS_TTL = 300.0


def ensure_weekly_award(db, now_utc=None):
    """Lazily decide last completed week's winner (idempotent). Returns the award row or None."""
    week_start, start, end = week_bounds(now_utc, weeks_back=1)
    key = week_start.isoformat()
    ck = (DATABASE, key)
    hit = _AWARD_CACHE.get(ck)
    if hit is not None and hit[0] is None:
        return hit[1]  # decided award: never changes
    # "No winner yet" stays valid until any new reaction lands (checked via O(1) MAX(rowid)),
    # so other workers' reactions are seen immediately; TTL is just a safety net.
    max_rx = db.execute("SELECT COALESCE(MAX(id), 0) FROM reactions").fetchone()[0]
    if hit is not None and hit[2] == max_rx and hit[0] > time.monotonic():
        return None
    row = db.execute("SELECT * FROM awards WHERE week_start = ?", (key,)).fetchone()
    if row:
        with _AWARD_LOCK:
            _AWARD_CACHE[ck] = (None, row, None)
        return row
    win = top_post_between(db, start, end)
    if not win:
        with _AWARD_LOCK:
            _AWARD_CACHE[ck] = (time.monotonic() + AWARD_MISS_TTL, None, max_rx)
        return None  # nobody reacted; re-checked after the short TTL
    cur = db.execute(
        "INSERT OR IGNORE INTO awards (week_start, post_id, user_id, reaction_count, created_at, target_type) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (key, win["id"], win["user_id"], win["n"], _now_utc().isoformat(), win["kind"]),
    )
    if cur.rowcount == 1:
        notify(db, win["user_id"], None, "award", win["kind"], win["id"])
    db.commit()
    row = db.execute("SELECT * FROM awards WHERE week_start = ?", (key,)).fetchone()
    if row:
        with _AWARD_LOCK:
            _AWARD_CACHE[ck] = (None, row, None)
    return row


def to_central(value):
    """The one UTC->Central converter. Accepts a stored naive-UTC ISO string or a naive-UTC
    datetime; returns an aware America/Chicago datetime (CST/CDT handled by zoneinfo), or None."""
    if not value:
        return None
    try:
        dt = value if isinstance(value, datetime) else datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(CENTRAL)


@app.template_filter("ct_time")
def ct_time(value):
    """Stored UTC -> 'Oct 30, 3:26 PM CDT' (adds the year if it isn't this year in Central)."""
    dt = to_central(value)
    if dt is None:
        return ""
    year = f", {dt.year}" if dt.year != to_central(_now_utc()).year else ""
    return f"{dt.strftime('%b')} {dt.day}{year}, {dt.strftime('%-I:%M %p')} {dt.tzname()}"


def award_count(db, user_id):
    return db.execute("SELECT COUNT(*) FROM awards WHERE user_id = ?", (user_id,)).fetchone()[0]


def _week_label(week_start):
    end = week_start + timedelta(days=6)
    if week_start.month == end.month:
        return f"{week_start.strftime('%b')} {week_start.day}–{end.day}"
    return f"{week_start.strftime('%b')} {week_start.day} – {end.strftime('%b')} {end.day}"


def _wants_json():
    return request.headers.get("X-Requested-With") == "fetch" or \
        "application/json" in (request.headers.get("Accept") or "")


@app.route("/react/<kind>/<int:target_id>", methods=["POST"])
def toggle_reaction(kind, target_id):
    viewer = require_user()
    if not viewer:
        if _wants_json():
            return jsonify({"ok": False, "error": "login required"}), 401
        return redirect(url_for("login"))
    table = REACTION_TARGETS.get(kind)
    if not table:
        return (jsonify({"ok": False, "error": "bad target"}), 404) if _wants_json() else redirect(url_for("index"))
    emoji = _REACTION_LOOKUP.get(_norm_emoji(request.form.get("emoji")))
    back = request.referrer or url_for("index")
    if not emoji:
        if _wants_json():
            return jsonify({"ok": False, "error": "emoji not allowed"}), 400
        flash("That reaction isn't on the menu.")
        return redirect(back)
    db = get_db()
    if not db.execute(f"SELECT 1 FROM {table} WHERE id = ?", (target_id,)).fetchone():
        if _wants_json():
            return jsonify({"ok": False, "error": "not found"}), 404
        flash("That post is gone.")
        return redirect(back)
    cur = db.execute(
        "DELETE FROM reactions WHERE target_type = ? AND target_id = ? AND user_id = ? AND emoji = ?",
        (kind, target_id, viewer["id"], emoji),
    )
    on = False
    if cur.rowcount == 0:
        ins = db.execute(
            "INSERT OR IGNORE INTO reactions (target_type, target_id, user_id, emoji, created_at) VALUES (?, ?, ?, ?, ?)",
            (kind, target_id, viewer["id"], emoji, datetime.utcnow().isoformat()),
        )
        on = True
        if ins.rowcount == 1:
            owner_col = "user_id" if kind == "post" else "author_id"
            owner = db.execute(f"SELECT {owner_col} AS uid FROM {table} WHERE id = ?", (target_id,)).fetchone()
            if owner:
                notify(db, owner["uid"], viewer["id"], "reaction", kind, target_id, emoji)
                if owner["uid"] == viewer["id"]:
                    db.execute(
                        f"UPDATE {table} SET self_reacted_at = ? WHERE id = ? AND self_reacted_at IS NULL",
                        (_now_utc().isoformat(), target_id),
                    )
    else:
        # Un-react: drop the matching unread notification.
        db.execute(
            "DELETE FROM notifications WHERE kind = 'reaction' AND actor_id = ? AND target_type = ? "
            "AND target_id = ? AND emoji = ? AND read_at IS NULL",
            (viewer["id"], kind, target_id, emoji),
        )
    db.commit()
    if _wants_json():
        rx = load_reactions(db, kind, [target_id], viewer["id"])[target_id]
        bar = get_template_attribute("_reactions.html", "reaction_bar")
        mark = db.execute(f"SELECT self_reacted_at FROM {table} WHERE id = ?", (target_id,)).fetchone()
        return jsonify({"ok": True, "on": on, "html": str(bar(kind, target_id, rx)),
                        "self_reacted": bool(mark and mark["self_reacted_at"])})
    anchor = ("#post-%d" if kind == "post" else "#bp-%d") % target_id
    return redirect(back.split("#")[0] + anchor)


def _cheek_squeak_context(db, viewer):
    """Banner data: last completed week's winner + this week's leader so far."""
    award = ensure_weekly_award(db)
    week_start, _, _ = week_bounds(weeks_back=1)
    out = {"label": _week_label(week_start), "winner": None, "leader": None}
    if award:
        kind = award["target_type"] or "post"
        if kind == "board":
            row = db.execute(
                "SELECT b.id, b.author_id AS user_id, b.body AS content, b.audio_path, b.created_at, b.self_reacted_at, "
                "COALESCE(u.username, 'unknown') AS username, o.username AS board_owner "
                "FROM board_posts b LEFT JOIN users u ON u.id = b.author_id "
                "LEFT JOIN users o ON o.id = b.board_user_id WHERE b.id = ?",
                (award["post_id"],),
            ).fetchone()
        else:
            row = db.execute(
                "SELECT p.id, p.user_id, p.content, p.audio_path, p.created_at, p.self_reacted_at, "
                "COALESCE(u.username, 'unknown') AS username, NULL AS board_owner "
                "FROM posts p LEFT JOIN users u ON u.id = p.user_id WHERE p.id = ?",
                (award["post_id"],),
            ).fetchone()
        if row:
            w = dict(row)
            w["kind"] = kind
            w["reaction_count"] = award["reaction_count"]
            w["reactions"] = load_reactions(db, kind, [w["id"]], viewer["id"]).get(w["id"], [])
            out["winner"] = w
    _, cs, ce = week_bounds(weeks_back=0)
    lead = top_post_between(db, cs, ce)
    if lead:
        u = db.execute("SELECT username FROM users WHERE id = ?", (lead["user_id"],)).fetchone()
        out["leader"] = {"id": lead["id"], "n": lead["n"], "kind": lead["kind"],
                         "anchor": ("bp-%d" if lead["kind"] == "board" else "post-%d") % lead["id"],
                         "username": u["username"] if u else "unknown"}
    if not out["winner"] and not out["leader"]:
        return None
    return out


@app.route("/notifications")
def notifications_page():
    viewer = require_user()
    if not viewer:
        return redirect(url_for("login"))
    db = get_db()
    ensure_weekly_award(db)
    prune_notifications(db, viewer["id"])
    rows = db.execute(
        """
        SELECT n.*, a.username AS actor_name,
               p.content AS post_text,
               b.body AS board_text, bo.username AS board_owner
        FROM notifications n
        LEFT JOIN users a ON a.id = n.actor_id
        LEFT JOIN posts p ON n.target_type = 'post' AND p.id = n.target_id
        LEFT JOIN board_posts b ON n.target_type = 'board' AND b.id = n.target_id
        LEFT JOIN users bo ON bo.id = b.board_user_id
        WHERE n.user_id = ?
        ORDER BY n.created_at DESC, n.id DESC
        LIMIT ?
        """,
        (viewer["id"], NOTIFY_KEEP),
    ).fetchall()
    items, by_key = [], {}
    for r in rows:
        if r["target_type"] == "post":
            link = url_for("index") + "#post-%d" % r["target_id"]
            snippet = r["post_text"] or ""
        elif r["target_type"] == "board":
            owner = r["board_owner"] or viewer["username"]
            link = url_for("user_profile", username=owner) + "#bp-%d" % r["target_id"]
            snippet = r["board_text"] or ""
        else:
            link, snippet = url_for("index"), ""
        if len(snippet) > 60:
            snippet = snippet[:57].rstrip() + "…"
        # Group several reactions from the same person on the same post into one line.
        if r["kind"] == "reaction":
            key = (r["actor_id"], r["target_type"], r["target_id"])
            if key in by_key:
                it = by_key[key]
                if r["emoji"] and r["emoji"] not in it["emojis"]:
                    it["emojis"].append(r["emoji"])
                it["unread"] = it["unread"] or r["read_at"] is None
                continue
        it = {
            "kind": r["kind"],
            "actor": r["actor_name"] or "Someone",
            "emojis": [r["emoji"]] if r["emoji"] else [],
            "target_type": r["target_type"],
            "link": link,
            "snippet": snippet,
            "created_at": r["created_at"] or "",
            "unread": r["read_at"] is None,
        }
        if r["kind"] == "reaction":
            by_key[(r["actor_id"], r["target_type"], r["target_id"])] = it
        items.append(it)
    db.execute(
        "UPDATE notifications SET read_at = ? WHERE user_id = ? AND read_at IS NULL",
        (_now_utc().isoformat(), viewer["id"]),
    )
    db.commit()
    g._unread_n = 0
    return render_template("notifications.html", items=items, username=session.get("username"))


FEED_PAGE = 20


def _feed_cursor(item):
    return "%s~%s~%d" % (item["created_at"] or "", item["kind"], item["id"])


def _parse_feed_cursor(raw):
    """'created_at~kind~id' -> tuple, or None. Order key is (created_at, kind, id) descending."""
    try:
        ts, kind, ident = (raw or "").rsplit("~", 2)
        if kind not in ("post", "board"):
            return None
        return ts, kind, int(ident)
    except (ValueError, AttributeError):
        return None


def _older_than(col_ts, col_id, kind, cur):
    """SQL + params selecting rows strictly after `cur` in (created_at, kind, id) DESC order."""
    if not cur:
        return "1=1", []
    ts, ckind, cid = cur
    # 'post' > 'board' as strings, so at equal timestamps posts come first.
    if kind == ckind:
        return f"(COALESCE({col_ts}, '') < ? OR (COALESCE({col_ts}, '') = ? AND {col_id} < ?))", [ts, ts, cid]
    if kind < ckind:  # board rows at the same timestamp come after a post cursor
        return f"COALESCE({col_ts}, '') <= ?", [ts]
    return f"COALESCE({col_ts}, '') < ?", [ts]


def _feed_page(db, viewer, viewer_admin, cur):
    """Up to FEED_PAGE non-pinned posts + board toots older than `cur`; returns (items, next_cursor)."""
    where, args = _older_than("posts.created_at", "posts.id", "post", cur)
    rows = db.execute(
        """
        SELECT posts.id, posts.user_id, posts.content, posts.created_at, posts.audio_path,
               posts.pinned_at, posts.self_reacted_at, COALESCE(users.username, 'unknown') AS username
        FROM posts
        LEFT JOIN users ON posts.user_id = users.id
        WHERE posts.pinned_at IS NULL AND """ + where + """
        ORDER BY COALESCE(posts.created_at, '') DESC, posts.id DESC
        LIMIT ?
        """,
        args + [FEED_PAGE + 1],
    ).fetchall()
    posts = [_post_item(r, viewer, viewer_admin) for r in rows]
    bwhere, bargs = _older_than("b.created_at", "b.id", "board", cur)
    board_rows = db.execute(
        """
        SELECT b.id, b.board_user_id, b.author_id, b.body, b.audio_path, b.created_at, b.self_reacted_at,
               COALESCE(a.username, 'unknown') AS username, o.username AS board_owner
        FROM board_posts b
        LEFT JOIN users a ON a.id = b.author_id
        LEFT JOIN users o ON o.id = b.board_user_id
        WHERE """ + bwhere + """
        ORDER BY COALESCE(b.created_at, '') DESC, b.id DESC
        LIMIT ?
        """,
        bargs + [FEED_PAGE + 1],
    ).fetchall()
    boards = [{
        "kind": "board",
        "id": r["id"],
        "user_id": r["author_id"],
        "content": r["body"],
        "created_at": r["created_at"] or "",
        "audio_path": r["audio_path"],
        "username": r["username"],
        "board_owner": r["board_owner"],
        "pinned": False,
        "self_reacted": bool(r["self_reacted_at"]),
        "can_pin": False,
        "can_manage": can_delete_board_post(viewer, r),
    } for r in board_rows]
    merged = sorted(posts + boards, key=lambda p: (p["created_at"] or "", p["kind"], p["id"]), reverse=True)
    page = merged[:FEED_PAGE]
    next_cursor = _feed_cursor(page[-1]) if len(merged) > FEED_PAGE else None
    return page, next_cursor


def _post_item(row, viewer, viewer_admin):
    return {
        "kind": "post",
        "id": row["id"],
        "user_id": row["user_id"],
        "content": row["content"],
        "created_at": row["created_at"] or "",
        "audio_path": row["audio_path"],
        "username": row["username"],
        "pinned": bool(row["pinned_at"]),
        "self_reacted": bool(row["self_reacted_at"]),
        "can_pin": can_pin_post(viewer, row["user_id"], viewer_admin),
        "can_manage": can_manage_post(viewer, row["user_id"]),
    }


def _attach_reactions(db, items, viewer):
    for kind in ("post", "board"):
        ids = [p["id"] for p in items if p["kind"] == kind]
        if not ids:
            continue
        rx = load_reactions(db, kind, ids, viewer["id"])
        for p in items:
            if p["kind"] == kind:
                p["reactions"] = rx.get(p["id"], [])


@app.route("/")
def index():
    viewer = require_user()
    if not viewer:
        if request.args.get("partial") and _wants_json():
            return jsonify({"ok": False, "error": "login required"}), 401
        return redirect(url_for("login"))
    db = get_db()
    viewer_admin = is_admin_user(viewer)
    raw_cursor = request.args.get("before")
    cur = _parse_feed_cursor(raw_cursor) if raw_cursor else None
    first_page = cur is None
    stream, next_cursor = _feed_page(db, viewer, viewer_admin, cur)
    if request.args.get("partial") and _wants_json():
        # "Load more": just the next batch of cards.
        _attach_reactions(db, stream, viewer)
        html = render_template("_feed_cards.html", posts=stream)
        return jsonify({"ok": True, "html": html, "next": next_cursor})
    pinned = []
    if first_page:
        # Opening The Back Draft marks everything read; only write when something is unread.
        if unread_back_draft_count(viewer["id"]):
            db.execute("UPDATE users SET back_draft_seen_at = ? WHERE id = ?",
                       (datetime.utcnow().isoformat(), viewer["id"]))
            db.commit()
        g._unread_bd = 0
        # Pinned posts first (newest pin on top), then the normal feed without them.
        pinned_rows = db.execute(
            """
            SELECT posts.id, posts.user_id, posts.content, posts.created_at, posts.audio_path,
                   posts.pinned_at, posts.self_reacted_at, COALESCE(users.username, 'unknown') AS username
            FROM posts
            LEFT JOIN users ON posts.user_id = users.id
            WHERE posts.pinned_at IS NOT NULL ORDER BY posts.pinned_at DESC, posts.id DESC
            """
        ).fetchall()
        pinned = [_post_item(r, viewer, viewer_admin) for r in pinned_rows]
    posts = pinned + stream
    _attach_reactions(db, posts, viewer)
    squeak = _cheek_squeak_context(db, viewer) if first_page else None
    return render_template(
        "feed.html",
        squeak=squeak,
        posts=posts,
        next_cursor=next_cursor,
        first_page=first_page,
        username=session.get("username"),
        is_admin=viewer_admin,
        post_max=POST_MAX_CHARS,
    )

# Bootstrap code: only works while the site has zero accounts (creates the owner/admin).
# After that, new members need a single-use invite from an admin (see /invites).
INVITE_CODE = os.environ.get("CUPOCHEESE_INVITE", "owner-only-cupocheese")


def load_invite(db, code):
    """Return the invite row if it exists (any state), else None."""
    code = (code or "").strip()
    if not code:
        return None
    return db.execute("SELECT * FROM invites WHERE code = ?", (code,)).fetchone()


def invite_status(row):
    if not row:
        return "invalid"
    if row["revoked_at"]:
        return "revoked"
    if row["used_at"]:
        return "used"
    return "pending"


INVITE_BAD_MSG = {
    "invalid": "That invite code doesn't smell right. Ask an admin for a fresh one.",
    "used": "That invite has already been used. Ask an admin for a fresh one.",
    "revoked": "That invite was revoked. Ask an admin for a fresh one.",
}


@app.route("/join/<code>")
def join(code):
    return redirect(url_for("register", invite=code))


@app.route("/register", methods=["GET", "POST"])
def register():
    db = get_db()
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        password_confirm = request.form.get("password_confirm", "")
        invite = request.form.get("invite", "").strip()
        first_name = clean_name(request.form.get("first_name"))
        last_name = clean_name(request.form.get("last_name"))
        back = url_for("register", invite=invite) if invite else url_for("register")
        user_count = db.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
        inv = None
        bootstrap = False
        if user_count == 0 and invite == INVITE_CODE:
            bootstrap = True  # very first account = owner/admin
        else:
            inv = load_invite(db, invite)
            st = invite_status(inv)
            if st != "pending":
                flash(INVITE_BAD_MSG.get(st) if invite else "Signups are invite-only. You need an invite.")
                return redirect(back)
        if not username or not email or not password:
            flash("Username, email, and password required")
            return redirect(back)
        if not first_name or not last_name:
            flash("First and last name required (only admins can see them).")
            return redirect(back)
        if "@" not in email or "." not in email.split("@")[-1]:
            flash("Enter a valid email address")
            return redirect(back)
        if inv is not None and inv["email"] and inv["email"].strip().lower() != email:
            flash("This invite is for a different email address. Use the email it was sent to.")
            return redirect(back)
        if password != password_confirm:
            flash("Passwords must match")
            return redirect(back)
        uerr = username_error(db, username)
        if uerr:
            flash(uerr)
            return redirect(back)
        if db.execute("SELECT 1 FROM users WHERE lower(email) = lower(?)", (email,)).fetchone():
            flash("Email already registered")
            return redirect(back)
        now = datetime.utcnow().isoformat()
        try:
            cur = db.execute(
                "INSERT INTO users (username, email, password_hash, created_at, is_admin, member_no, back_draft_seen_at, first_name, last_name) "
                "VALUES (?, ?, ?, ?, ?, (SELECT COALESCE(MAX(member_no), 0) + 1 FROM users), ?, ?, ?)",
                (username, email, generate_password_hash(password), now, 1 if bootstrap else 0, now, first_name, last_name)
            )
            new_id = cur.lastrowid
            if inv is not None:
                claimed = db.execute(
                    "UPDATE invites SET used_by = ?, used_at = ? WHERE id = ? AND used_at IS NULL AND revoked_at IS NULL",
                    (new_id, now, inv["id"]),
                ).rowcount
                if claimed != 1:
                    db.rollback()
                    flash(INVITE_BAD_MSG["used"])
                    return redirect(back)
            db.commit()
        except sqlite3.IntegrityError as e:
            db.rollback()
            if "email" in str(e).lower():
                flash("Email already registered")
            else:
                flash("Username already taken")
            return redirect(back)
        session.clear()
        session["user_id"] = new_id
        session["username"] = username
        flash("Account Created! Hike a leg and come on in!")
        return redirect(url_for("welcome"))
    code = request.args.get("invite", "").strip()
    inv = load_invite(db, code) if code else None
    status = invite_status(inv) if code else None
    if code and status != "pending" and code == INVITE_CODE:
        status = None  # bootstrap code: don't advertise it as bad
    return render_template(
        "register.html",
        invite_code=code,
        invite_status=status,
        invite_email=(inv["email"] if inv is not None and status == "pending" else "") or "",
        invite_bad_msg=INVITE_BAD_MSG.get(status) if status and status != "pending" else None,
    )

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
            return redirect(url_for("welcome"))
        flash("Invalid username or password")
    return render_template("login.html")

@app.route("/welcome")
def welcome():
    """Landing page after sign-in. Copy lives in templates/welcome.html."""
    viewer = require_user()
    if not viewer:
        return redirect(url_for("login"))
    return render_template("welcome.html", username=session.get("username"), post_max=POST_MAX_CHARS)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/add-name", methods=["GET", "POST"])
def add_name():
    """One-time stop for members who joined before names were required."""
    user = require_user()
    if not user:
        return redirect(url_for("login"))
    if request.method == "POST":
        first_name = clean_name(request.form.get("first_name"))
        last_name = clean_name(request.form.get("last_name"))
        if not first_name or not last_name:
            flash("Both first and last name, please.")
            return render_template("add_name.html", first_name=first_name, last_name=last_name), 400
        db = get_db()
        db.execute("UPDATE users SET first_name = ?, last_name = ? WHERE id = ?", (first_name, last_name, user["id"]))
        db.commit()
        flash("Thanks! Now go let 'er rip.")
        return redirect(url_for("index"))
    if has_real_name(user):
        return redirect(url_for("index"))
    return render_template("add_name.html", first_name=user["first_name"] or "", last_name=user["last_name"] or "")

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
    if "/board" in (request.path or ""):
        flash("That clip is too large (max 15 MB). Try a shorter recording.")
        return redirect(request.referrer or url_for("index"))
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
    admin = is_admin_user(user)
    if len(content) > POST_MAX_CHARS:
        flash(MSG_TOO_LONG)
        return redirect(url_for("index"))
    clip_name, err = _save_audio_upload(request.files.get("audio"), prefix="")
    if err:
        flash(err)
        return redirect(url_for("index"))
    if not clip_name and not admin:
        flash(MSG_NO_TOOT)
        return redirect(url_for("index"))
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


def can_pin_post(viewer, owner_id, viewer_admin=None):
    """Only admins, and only their own posts."""
    if not viewer or owner_id is None:
        return False
    if viewer_admin is None:
        viewer_admin = is_admin_user(viewer)
    return bool(viewer_admin) and int(viewer["id"]) == int(owner_id)


@app.route("/post/<int:post_id>/pin", methods=["POST"])
def pin_post(post_id):
    viewer = require_user()
    if not viewer:
        return redirect(url_for("login"))
    db = get_db()
    post = db.execute("SELECT id, user_id, pinned_at FROM posts WHERE id = ?", (post_id,)).fetchone()
    if not post:
        abort(404)
    if not can_pin_post(viewer, post["user_id"]):
        abort(403)
    action = request.form.get("action", "toggle")
    pin = (post["pinned_at"] is None) if action == "toggle" else (action == "pin")
    db.execute(
        "UPDATE posts SET pinned_at = ? WHERE id = ?",
        (datetime.utcnow().isoformat() if pin else None, post_id),
    )
    db.commit()
    flash("📌 Pinned to the top of The Back Draft." if pin else "Unpinned.")
    back = request.referrer or url_for("index")
    return redirect(back.split("#")[0] + "#post-%d" % post_id)


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
    delete_reactions(db, "post", post_id)
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
        if len(content) > POST_MAX_CHARS:
            flash(MSG_TOO_LONG)
            return render_template(
                "edit_post.html",
                post=post,
                content=content[:POST_MAX_CHARS],
                post_max=POST_MAX_CHARS,
                username=session.get("username"),
            )
        if not content and not audio:
            flash("Add some text or keep a clip — empty posts aren't allowed.")
            return render_template(
                "edit_post.html",
                post=post,
                content="",
                post_max=POST_MAX_CHARS,
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
        post_max=POST_MAX_CHARS,
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
            "SELECT id, content, created_at, audio_path, pinned_at, self_reacted_at FROM posts WHERE id = ? AND user_id = ?",
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
        moved = db.execute(
            "SELECT u.username FROM username_history h JOIN users u ON u.id = h.user_id "
            "WHERE lower(h.old_username) = lower(?) ORDER BY h.id DESC LIMIT 1", (username,)
        ).fetchone()
        if moved:
            return redirect(url_for("user_profile", username=moved["username"]))
        flash("No member by that name.")
        return redirect(url_for("index"))
    ensure_weekly_award(db)
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
            "pinned": bool(post["pinned_at"]),
            "self_reacted": bool(post["self_reacted_at"]),
            "can_pin": can_pin_post(viewer, profile["id"], viewer_admin),
        })
    board = _load_board(db, profile["id"], viewer)
    top_rx = load_reactions(db, "post", [t["id"] for t in tops], viewer["id"])
    for t in tops:
        t["reactions"] = top_rx.get(t["id"], [])
    board_rx = load_reactions(db, "board", [b["id"] for b in board], viewer["id"])
    for b in board:
        b["reactions"] = board_rx.get(b["id"], [])
    return render_template(
        "profile.html",
        profile=profile,
        tops=tops,
        board=board,
        board_max=BOARD_MAX_CHARS,
        is_owner=is_owner,
        username=session.get("username"),
        is_admin=viewer_admin,
        admin=admin_info(db, profile, viewer) if viewer_admin else None,
        squeak_wins=award_count(db, profile["id"]),
    )


BOARD_MAX_CHARS = POST_MAX_CHARS
BOARD_LIST_LIMIT = 100


def can_delete_board_post(viewer, board_post):
    """Author, board owner, or admin may delete a Cheese Board post."""
    if not viewer or not board_post:
        return False
    if viewer["id"] in (board_post["author_id"], board_post["board_user_id"]):
        return True
    return is_admin_user(viewer)


def clip_duration_seconds(path):
    """Best-effort duration via mutagen (ogg/opus, mp4/m4a, mp3, wav). None if unknown (e.g. webm)."""
    try:
        import mutagen
        f = mutagen.File(path)
        length = float(f.info.length) if f is not None and getattr(f, "info", None) else 0.0
    except Exception:
        return None
    if not length or length != length or length <= 0:  # 0/NaN -> unknown (e.g. fragmented mp4)
        return None
    return length


def _save_audio_upload(clip, prefix="bd_"):
    """Save an uploaded audio clip into UPLOAD_FOLDER. Returns (filename|None, error|None)."""
    if not clip or not getattr(clip, "filename", None):
        return None, None
    name = secure_filename(clip.filename or "clip.webm") or "clip.webm"
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
    if ext not in ALLOWED_AUDIO_EXT:
        return None, "Unsupported audio type. Try recording again."
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    clip_name = datetime.utcnow().strftime("%Y%m%d%H%M%S") + "_" + prefix + secrets.token_hex(8) + ext
    dest = os.path.join(UPLOAD_FOLDER, clip_name)
    try:
        clip.save(dest)
        size = os.path.getsize(dest)
        if size == 0 or size > MAX_AUDIO_BYTES:
            os.remove(dest)
            return None, "Clip could not be saved (empty or too large)."
        secs = clip_duration_seconds(dest)
        too_long = (secs > MAX_CLIP_SECONDS + CLIP_SECONDS_SLACK) if secs is not None \
            else size > UNKNOWN_DURATION_MAX_BYTES
        if too_long:
            os.remove(dest)
            return None, CLIP_TOO_LONG_MSG
    except OSError:
        return None, "Could not store clip on server."
    return clip_name, None


def _load_board(db, board_user_id, viewer):
    rows = db.execute(
        """
        SELECT b.id, b.board_user_id, b.author_id, b.body, b.audio_path, b.created_at, b.self_reacted_at,
               u.username AS author_username, u.avatar_path AS author_avatar
        FROM board_posts b
        LEFT JOIN users u ON u.id = b.author_id
        WHERE b.board_user_id = ?
        ORDER BY b.created_at DESC, b.id DESC
        LIMIT ?
        """,
        (board_user_id, BOARD_LIST_LIMIT),
    ).fetchall()
    return [
        {
            "id": r["id"],
            "body": r["body"],
            "audio_path": r["audio_path"],
            "created_at": r["created_at"] or "",
            "author_username": r["author_username"],
            "author_avatar": r["author_avatar"],
            "self_reacted": bool(r["self_reacted_at"]),
            "can_delete": can_delete_board_post(viewer, r),
        }
        for r in rows
    ]


@app.route("/u/<username>/board", methods=["POST"])
def board_post(username):
    viewer = require_user()
    if not viewer:
        return redirect(url_for("login"))
    db = get_db()
    owner = db.execute("SELECT id, username FROM users WHERE username = ?", (username,)).fetchone()
    if not owner:
        flash("No member by that name.")
        return redirect(url_for("people"))
    back = url_for("user_profile", username=owner["username"]) + "#board"
    body = (request.form.get("body") or "").strip()
    if len(body) > BOARD_MAX_CHARS:
        flash(MSG_TOO_LONG)
        return redirect(back)
    clip_name, err = _save_audio_upload(request.files.get("audio"))
    if err:
        flash(err)
        return redirect(back)
    if not clip_name and not is_admin_user(viewer):
        flash(MSG_NO_TOOT)
        return redirect(back)
    if not body and not clip_name:
        flash("Add some words or a clip before slapping it on the board.")
        return redirect(back)
    cur = db.execute(
        "INSERT INTO board_posts (board_user_id, author_id, body, audio_path, created_at) VALUES (?, ?, ?, ?, ?)",
        (owner["id"], viewer["id"], body, clip_name, datetime.utcnow().isoformat()),
    )
    notify(db, owner["id"], viewer["id"], "board_post", "board", cur.lastrowid)
    db.commit()
    flash("Pinned to the Cheese Board. 🧀")
    return redirect(back)


@app.route("/board/<int:post_id>/delete", methods=["POST"])
def delete_board_post(post_id):
    viewer = require_user()
    if not viewer:
        return redirect(url_for("login"))
    db = get_db()
    bp = db.execute(
        """
        SELECT b.id, b.board_user_id, b.author_id, b.audio_path, u.username AS board_username
        FROM board_posts b LEFT JOIN users u ON u.id = b.board_user_id
        WHERE b.id = ?
        """,
        (post_id,),
    ).fetchone()
    if not bp:
        flash("That board post is already gone.")
        return redirect(request.referrer or url_for("index"))
    back = (
        url_for("user_profile", username=bp["board_username"]) + "#board"
        if bp["board_username"] else url_for("index")
    )
    nxt = request.form.get("next") or ""
    if nxt.startswith("/") and not nxt.startswith("//"):
        back = nxt
    if not can_delete_board_post(viewer, bp):
        flash("Only the author, the board owner, or an admin can remove that.")
        return redirect(back)
    db.execute("DELETE FROM board_posts WHERE id = ?", (post_id,))
    delete_reactions(db, "board", post_id)
    db.commit()
    if bp["audio_path"]:
        path = os.path.join(UPLOAD_FOLDER, bp["audio_path"])
        if os.path.isfile(path):
            try:
                os.remove(path)
            except OSError:
                pass
    flash("Board post scraped off.")
    return redirect(back)


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
    viewer_admin = is_admin_user(viewer)
    members = []
    for row in rows:
        full = db.execute("SELECT * FROM users WHERE id = ?", (row["id"],)).fetchone()
        members.append({
            "id": row["id"],
            "username": row["username"],
            "avatar_path": row["avatar_path"],
            "created_at": row["created_at"],
            "is_you": row["id"] == viewer["id"],
            "admin": admin_info(db, full, viewer) if viewer_admin else None,
        })
    return render_template(
        "people.html",
        members=members,
        viewer_admin=viewer_admin,
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
        first_name = clean_name(request.form.get("first_name"))
        last_name = clean_name(request.form.get("last_name"))
        if not first_name or not last_name:
            flash("First and last name can't be blank (only admins can see them).")
            return redirect(url_for("edit_profile"))
        new_username = (request.form.get("username") or "").strip()
        rename_to = None
        if new_username and new_username != user["username"]:
            unlock = username_unlock_at(user)
            if unlock:
                flash(f"You can change your username again on {ct_date(unlock)}.")
                return redirect(url_for("edit_profile"))
            uerr = username_error(db, new_username, exclude_user_id=user["id"])
            if uerr:
                flash(uerr)
                return redirect(url_for("edit_profile"))
            rename_to = new_username

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
        db.execute("UPDATE users SET first_name = ?, last_name = ? WHERE id = ?", (first_name, last_name, user["id"]))
        if rename_to:
            try:
                rename_user(db, user, rename_to)
            except sqlite3.IntegrityError:
                db.rollback()
                flash("Username already taken")
                return redirect(url_for("edit_profile"))
        db.commit()
        if rename_to:
            session["username"] = rename_to
            flash(f"Profile updated — you're now {rename_to}. Same cheese, new label.")
        else:
            flash("Profile updated — looking sharp (and fragrant).")
        return redirect(url_for("user_profile", username=rename_to or user["username"]))

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
        username_unlock=(ct_date(username_unlock_at(user)) if username_unlock_at(user) else None),
        username_days=USERNAME_CHANGE_DAYS,
        username_min=USERNAME_MIN,
        username_max=USERNAME_MAX,
    )



# ---- Admin tools: invites + admin designation (admins only) ----
def require_admin():
    """Return (viewer, None) for admins, else (None, response)."""
    viewer = require_user()
    if not viewer:
        return None, redirect(url_for("login"))
    if not is_admin_user(viewer):
        return None, (render_template("forbidden.html", username=session.get("username")), 403)
    return viewer, None


def _invite_url(code):
    base = os.environ.get("CUPOCHEESE_PUBLIC_URL", "").rstrip("/") or request.url_root.rstrip("/")
    # Render terminates TLS at its proxy; make shared links https.
    if base.startswith("http://") and request.headers.get("X-Forwarded-Proto", "").split(",")[0].strip() == "https":
        base = "https://" + base[len("http://"):]
    return base + url_for("join", code=code)


@app.route("/invites", methods=["GET", "POST"])
def invites_page():
    viewer, resp = require_admin()
    if resp:
        return resp
    db = get_db()
    new_code = None
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        if email and ("@" not in email or "." not in email.split("@")[-1]):
            flash("That email doesn't look right. Leave it blank for an open invite.")
            return redirect(url_for("invites_page"))
        if email and db.execute("SELECT 1 FROM users WHERE lower(email) = ?", (email,)).fetchone():
            flash("Somebody with that email is already in the Cup.")
            return redirect(url_for("invites_page"))
        code = secrets.token_urlsafe(12)
        db.execute(
            "INSERT INTO invites (code, email, created_by, created_at) VALUES (?, ?, ?, ?)",
            (code, email or None, viewer["id"], datetime.utcnow().isoformat()),
        )
        db.commit()
        flash("Fresh invite baked! 🎟️ Copy the link and send it to your stinky friend.")
        return redirect(url_for("invites_page", new=code))
    new_code = request.args.get("new", "").strip() or None
    rows = db.execute(
        """
        SELECT i.*, c.username AS creator_name, u.username AS used_name, r.username AS revoker_name
        FROM invites i
        LEFT JOIN users c ON c.id = i.created_by
        LEFT JOIN users u ON u.id = i.used_by
        LEFT JOIN users r ON r.id = i.revoked_by
        ORDER BY i.id DESC
        """
    ).fetchall()
    pending, done = [], []
    for r in rows:
        item = dict(r)
        item["status"] = invite_status(r)
        item["url"] = _invite_url(r["code"])
        (pending if item["status"] == "pending" else done).append(item)
    return render_template(
        "invites.html",
        pending=pending,
        done=done,
        new_code=new_code,
        username=session.get("username"),
    )


@app.route("/invites/<int:invite_id>/revoke", methods=["POST"])
def revoke_invite(invite_id):
    viewer, resp = require_admin()
    if resp:
        return resp
    db = get_db()
    n = db.execute(
        "UPDATE invites SET revoked_by = ?, revoked_at = ? WHERE id = ? AND used_at IS NULL AND revoked_at IS NULL",
        (viewer["id"], datetime.utcnow().isoformat(), invite_id),
    ).rowcount
    db.commit()
    flash("Invite revoked. That one's been flushed. 🚽" if n else "That invite was already used or revoked.")
    return redirect(url_for("invites_page"))


@app.route("/u/<username>/admin", methods=["POST"])
def set_admin(username):
    viewer, resp = require_admin()
    if resp:
        return resp
    db = get_db()
    target = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    back = request.form.get("next") or url_for("user_profile", username=username)
    if not back.startswith("/"):
        back = url_for("people")
    if not target:
        flash("No member by that name.")
        return redirect(url_for("people"))
    action = request.form.get("action", "")
    if action == "grant":
        db.execute("UPDATE users SET is_admin = 1 WHERE id = ?", (target["id"],))
        db.commit()
        flash(f"{target['username']} is now an admin. 💩 Badge earned!")
    elif action == "revoke":
        if target["id"] == viewer["id"]:
            flash("You can't remove your own admin status.")
        elif target["id"] == owner_user_id(db):
            flash("The owner's admin status can't be removed.")
        elif (target["username"] or "").strip().lower() in _admin_usernames():
            flash(f"{target['username']} is an admin via the CUPOCHEESE_ADMINS setting on Render. Remove them there.")
        else:
            db.execute("UPDATE users SET is_admin = 0 WHERE id = ?", (target["id"],))
            db.commit()
            flash(f"{target['username']} is no longer an admin.")
    else:
        flash("Unknown action.")
    return redirect(back)


def admin_info(db, user_row, viewer):
    """How a member's admin status is set, for admin-only controls."""
    env_admin = (user_row["username"] or "").strip().lower() in _admin_usernames()
    db_admin = int(user_row["is_admin"] or 0) == 1
    is_owner = user_row["id"] == owner_user_id(db)
    is_self = viewer is not None and user_row["id"] == viewer["id"]
    return {
        "is_admin": env_admin or db_admin,
        "env_admin": env_admin,
        "db_admin": db_admin,
        "is_owner": is_owner,
        "is_self": is_self,
        "can_grant": not (env_admin or db_admin),
        "can_revoke": db_admin and not env_admin and not is_owner and not is_self,
    }


# ---- Caching + health ----
YEAR = 31536000
IMMUTABLE_ENDPOINTS = {"serve_clip", "serve_avatar"}  # filenames are unique per upload, never reused
_STATIC_VERSIONS = {}


def static_v(filename):
    """url_for('static') with a content-hash ?v= so the file can be cached for a year."""
    v = _STATIC_VERSIONS.get(filename)
    if v is None:
        try:
            with open(os.path.join(app.static_folder, filename), "rb") as f:
                v = hashlib.sha1(f.read()).hexdigest()[:10]
        except OSError:
            v = "0"
        _STATIC_VERSIONS[filename] = v
    return url_for("static", filename=filename, v=v)


app.jinja_env.globals["static_v"] = static_v


def rx_glyph(key):
    """A reaction as HTML: the emoji itself, or an inline <img> for custom image reactions."""
    custom = CUSTOM_REACTIONS.get(key)
    if not custom:
        return escape(key or "")
    label, path = custom
    return Markup('<img class="rx-img" src="%s" alt="%s" title="%s" width="64" height="64">') % (
        static_v(path), label, label)


def rx_label(key):
    custom = CUSTOM_REACTIONS.get(key)
    return custom[0] if custom else (key or "")


app.jinja_env.globals["rx_glyph"] = rx_glyph
app.jinja_env.globals["rx_label"] = rx_label


@app.after_request
def _cache_headers(resp):
    ep = request.endpoint or ""
    if resp.status_code in (200, 206, 304):
        if ep in IMMUTABLE_ENDPOINTS:
            # Login-gated media: browser may keep it a year, shared caches may not.
            resp.headers["Cache-Control"] = f"private, max-age={YEAR}, immutable"
        elif ep == "static":
            if request.args.get("v"):
                resp.headers["Cache-Control"] = f"public, max-age={YEAR}, immutable"
            else:
                resp.headers["Cache-Control"] = "public, max-age=86400"
    return resp


@app.route("/healthz")
def healthz():
    """Render health check: process is up and the DB answers. No session, no templates."""
    try:
        get_db().execute("SELECT 1").fetchone()
    except sqlite3.Error:
        return ("db error", 503, {"Cache-Control": "no-store", "Content-Type": "text/plain"})
    return ("ok", 200, {"Cache-Control": "no-store", "Content-Type": "text/plain"})


# ---- PWA: manifest, service worker (root scope), offline fallback ----
THEME_COLOR = "#c47a12"
BG_COLOR = "#fff8e7"


@app.route("/manifest.webmanifest")
def pwa_manifest():
    data = {
        "name": "Cup O' Cheese",
        "short_name": "Cup O' Cheese",
        "description": "Invite-only audio social. Pitter patter, let's get at 'er.",
        "id": "/",
        "start_url": "/",
        "scope": "/",
        "display": "standalone",
        "orientation": "portrait",
        "theme_color": THEME_COLOR,
        "background_color": BG_COLOR,
        "icons": [
            {"src": url_for("static", filename="icons/icon-192.png"), "sizes": "192x192", "type": "image/png", "purpose": "any"},
            {"src": url_for("static", filename="icons/icon-512.png"), "sizes": "512x512", "type": "image/png", "purpose": "any"},
            {"src": url_for("static", filename="icons/icon-maskable-512.png"), "sizes": "512x512", "type": "image/png", "purpose": "maskable"},
        ],
    }
    resp = app.response_class(json.dumps(data, ensure_ascii=False), mimetype="application/manifest+json")
    resp.headers["Cache-Control"] = "no-cache"  # always revalidate (cheap 304 via ETag)
    resp.add_etag()
    return resp.make_conditional(request)


@app.route("/sw.js")
def service_worker():
    resp = send_from_directory(app.static_folder, "sw.js", mimetype="application/javascript", max_age=0)
    resp.headers["Cache-Control"] = "no-cache"
    resp.headers["Service-Worker-Allowed"] = "/"
    return resp


@app.route("/offline")
def offline():
    return render_template("offline.html")

init_db()
account_flow.register_routes(app, get_db)


def _log_admins():
    try:
        db = get_db()
        names = [r["username"] for r in db.execute(
            "SELECT username FROM users WHERE COALESCE(is_admin, 0) = 1 ORDER BY id")]
        owner = db.execute("SELECT username FROM users ORDER BY id LIMIT 1").fetchone()
        n = db.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
        db.close()
        print(f"[cupocheese] users={n} owner={owner['username'] if owner else None} "
              f"db_admins={names} env_admins={sorted(_admin_usernames())}", flush=True)
    except Exception as e:  # never block startup
        print(f"[cupocheese] admin log failed: {e}", flush=True)


_log_admins()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=os.environ.get("FLASK_DEBUG") == "1")