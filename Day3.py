import os
import re
import sqlite3
import subprocess

from flask import Flask, request, render_template


app = Flask(__name__)

app.config["DEBUG"] = False

DATABASE = "database.db"



def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    """)

    cursor.execute("""
        INSERT OR IGNORE INTO users (username, password, role)
        VALUES (?, ?, ?)
    """, ("alice", "pass123", "admin"))

    cursor.execute("""
        INSERT OR IGNORE INTO users (username, password, role)
        VALUES (?, ?, ?)
    """, ("bob", "hunter2", "user"))

    conn.commit()
    conn.close()


def is_valid_host(host):
    """
    يسمح بعنوان IPv4 أو IPv6 أو Hostname بسيط.
    لا يسمح بمسافات أو Shell Metacharacters.
    """

    if not host or len(host) > 253:
        return False

    # IPv4
    ipv4_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    if re.fullmatch(ipv4_pattern, host):
        parts = host.split(".")

        return all(0 <= int(part) <= 255 for part in parts)


    if ":" in host:
        return re.fullmatch(r"[0-9a-fA-F:]+", host) is not None

    hostname_pattern = (
        r"^(?=.{1,253}$)"
        r"(?:[A-Za-z0-9]"
        r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
        r"\.)*"
        r"[A-Za-z0-9]"
        r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
    )

    return re.fullmatch(hostname_pattern, host) is not None



@app.route("/user")
def get_user():
    username = request.args.get("name", "")

    if not username:
        return "Username is required.", 400

    conn = get_db()

    try:
        cursor = conn.cursor()
        query = """
            SELECT username, role
            FROM users
            WHERE username = ?
        """

        cursor.execute(query, (username,))
        user = cursor.fetchone()

    except sqlite3.Error:
        app.logger.exception("Database error in /user")
        return "Internal server error.", 500

    finally:
        conn.close()

    if user:
        return f"User found: {user['username']} (Role: {user['role']})"

    return "User not found.", 404


@app.route("/feedback")
def feedback():
    msg = request.args.get("msg", "No message provided")
    return render_template("feedback.html", msg=msg)


@app.route("/tools/ping")
def ping_host():
    host = request.args.get("host", "127.0.0.1")

    if not is_valid_host(host):
        return "Invalid host.", 400

    try:
        output = subprocess.run(
            ["ping", "-c", "1", host],
            capture_output=True,
            text=True,
            timeout=5,
            check=True
        )

        return render_template(
            "ping.html",
            output=output.stdout
        )

    except subprocess.TimeoutExpired:
        return "Ping request timed out.", 504

    except subprocess.CalledProcessError:
        return "Ping failed.", 500


@app.errorhandler(404)
def page_not_found(error):
    return "Page not found.", 404


@app.errorhandler(500)
def internal_server_error(error):
    return "Internal server error.", 500



if __name__ == "__main__":
    init_db()
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
