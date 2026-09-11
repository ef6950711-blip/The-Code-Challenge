import os
import sqlite3
from functools import wraps

from flask import Flask, request, render_template, redirect, url_for, session, g
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)

app.secret_key = os.environ.get("SECRET_KEY")
if not app.secret_key:
    raise RuntimeError("SECRET_KEY is not configured")

DATABASE = "final_challenge.db"
UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "pdf", "txt"}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)

    if db is not None:
        db.close()


def init_db():
    db = get_db()

    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0,
            bio TEXT
        )
    """)

    existing_admin = db.execute(
        "SELECT id FROM users WHERE username = ?",
        ("admin",)
    ).fetchone()

    if not existing_admin:
        db.execute(
            """
            INSERT INTO users
            (username, password, is_admin, bio)
            VALUES (?, ?, ?, ?)
            """,
            (
                "admin",
                generate_password_hash(os.environ["ADMIN_PASSWORD"]),
                1,
                "System Administrator"
            )
        )

    db.commit()


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))

        return f(*args, **kwargs)

    return decorated


@app.route("/")
def index():
    if "user_id" in session:
        return render_template(
            "index.html",
            username=session["username"]
        )

    return render_template("home.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        db = get_db()

        user = db.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        if user and check_password_hash(user["password"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["is_admin"] = bool(user["is_admin"])

            return redirect(url_for("index"))

        return "Invalid Credentials", 401

    return render_template("login.html")


@app.route("/profile")
@login_required
def profile():
    requested_id = request.args.get("id", type=int)

    if requested_id is None:
        return "Missing ID", 400

    if requested_id != session["user_id"] and not session.get("is_admin"):
        return "Forbidden", 403

    db = get_db()

    user = db.execute(
        "SELECT username, bio, is_admin FROM users WHERE id = ?",
        (requested_id,)
    ).fetchone()

    if not user:
        return "User not found", 404

    return render_template(
        "profile.html",
        user=user
    )


@app.route("/upload", methods=["POST"])
@login_required
def upload_file():
    file = request.files.get("file")

    if not file or file.filename == "":
        return "No selected file", 400

    filename = secure_filename(file.filename)

    if not filename:
        return "Invalid filename", 400

    extension = filename.rsplit(".", 1)[-1].lower()

    if extension not in ALLOWED_EXTENSIONS:
        return "File type not allowed", 400

    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    safe_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        filename
    )

    file.save(safe_path)

    return "File uploaded successfully"


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


if __name__ == "__main__":
    with app.app_context():
        init_db()

    app.run(debug=False, port=5000)
