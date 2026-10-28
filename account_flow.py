import os
import secrets
from datetime import datetime, timedelta
from flask import request, redirect, url_for, flash, render_template
from werkzeug.security import generate_password_hash

LINK_HOURS = 1


def _owner_link_mode():
    if os.environ.get("CUPOCHEESE_OWNER_LINK", "").strip() == "1":
        return True
    return os.environ.get("CUPOCHEESE_SHOW_RESET_LINK", "").strip() == "1"

def _public_base():
    u = os.environ.get("CUPOCHEESE_PUBLIC_URL", "").rstrip("/")
    return u or request.url_root.rstrip("/")

def ensure_link_table(db):
    db.execute(
        "CREATE TABLE IF NOT EXISTS acct_links ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "uid INTEGER NOT NULL, "
        "code TEXT UNIQUE NOT NULL, "
        "exp TEXT, "
        "used TEXT, "
        "created TEXT)"
    )
    db.commit()

def issue_code(db, uid):
    code = secrets.token_urlsafe(32)
    now = datetime.utcnow()
    exp = (now + timedelta(hours=LINK_HOURS)).isoformat()
    

    db.execute(
        "INSERT INTO acct_links (uid, code, exp, created) VALUES (?, ?, ?, ?)",
        (uid, code, exp, now.isoformat()),
    )
    db.commit()
    return code


def load_code(db, code):
    row = db.execute(
        "SELECT acct_links.*, users.username, users.email "
        "FROM acct_links JOIN users ON users.id = acct_links.uid "
        "WHERE acct_links.code = ?",
        (code,),
    ).fetchone()
    if not row or row["used"]:
        return None
    try:
        exp = datetime.fromisoformat(row["exp"])
    except ValueError:
        return None
    if datetime.utcnow() > exp:
        return None
    return row


def register_routes(app, get_db):
    ensure_link_table(get_db())

    @app.route("/forgot", methods=["GET", "POST"])
    def forgot_password():
        link = None
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            db = get_db()
            ensure_link_table(db)
            user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            flash("If that account exists, a link was issued. It expires in 1 hour.")
            if user:
                code = issue_code(db, user["id"])
                path = url_for("reset_password", token=code)
                url = _public_base() + path
                email = ""
                try:
                    email = user["email"] or ""
                except (KeyError, IndexError):
                    email = ""
                app.logger.warning("acct link uid=%s email=%s url=%s", user["id"], email or "(none)", url)
                if email:
                    app.logger.info("would mail %s (no SMTP)", email)
                if _owner_link_mode():
                    link = url
                    flash("Owner recovery mode is on. Use this one-time link:")
            return render_template("forgot.html", reset_link=link)
        return render_template("forgot.html", reset_link=None)

    @app.route("/reset/<token>", methods=["GET", "POST"])
    def reset_password(token):
        db = get_db()
        ensure_link_table(db)
        row = load_code(db, token)
        if not row:
            flash("That link is invalid or expired. Request a new one.")
            return redirect(url_for("forgot_password"))
        if request.method == "POST":
            password = request.form.get("password", "")
            password_confirm = request.form.get("password_confirm", "")
            if not password:
                flash("Password required")
                return render_template("reset.html", token=token, username=row["username"])
            if password != password_confirm:
                flash("Passwords must match")
                return render_template("reset.html", token=token, username=row["username"])
            row = load_code(db, token)
            if not row:
                flash("That link is invalid or expired. Request a new one.")
                return redirect(url_for("forgot_password"))
            db.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (generate_password_hash(password), row["uid"]),
            )
            db.execute(
                "UPDATE acct_links SET used = ? WHERE id = ?",
                (datetime.utcnow().isoformat(), row["id"]),
            )
            db.commit()
            flash("Password updated. Log in with your new password.")
            return redirect(url_for("login"))
        return render_template("reset.html", token=token, username=row["username"])
