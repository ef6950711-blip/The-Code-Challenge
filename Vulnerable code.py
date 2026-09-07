import sqlite3
import subprocess
from flask import Flask, request

app = Flask(__name__)

def get_db():
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT,
            role TEXT
        )
    """)

    cursor.execute("DELETE FROM users")

    cursor.execute(
        "INSERT INTO users (username, password, role) VALUES ('alice', 'pass123', 'admin')"
    )

    cursor.execute(
        "INSERT INTO users (username, password, role) VALUES ('bob', 'hunter2', 'user')"
    )

    conn.commit()
    conn.close()

@app.route("/user")
def get_user():
    username = request.args.get("name", "")

    conn = get_db()
    cursor = conn.cursor()

    query = f"SELECT username, role FROM users WHERE username = '{username}'"

    try:
        cursor.execute(query)
        user = cursor.fetchone()
    except Exception as e:
        return f"Database error: {e}", 500

    if user:
        return f"User found: {user['username']} (Role: {user['role']})"

    return "User not found."

@app.route("/feedback")
def feedback():
    msg = request.args.get("msg", "No message provided")

    html = f"""
    <html>
    <head><title>Feedback Portal</title></head>
    <body>
    <h2>Message Received:</h2>
    <div>{msg}</div>
    </body>
    </html>
    """

    return html

@app.route("/tools/ping")
def ping_host():
    host = request.args.get("host", "127.0.0.1")

    command = f"ping -c 1 {host}"

    try:
        output = subprocess.check_output(
            command,
            shell=True,
            stderr=subprocess.STDOUT,
            text=True
        )

        return f"<pre>{output}</pre>"

    except subprocess.CalledProcessError as e:
        return f"<pre>Error:\n{e.output}</pre>", 500

if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5000)
