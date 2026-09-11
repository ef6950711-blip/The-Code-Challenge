import os
import sqlite3
from flask import Flask, request, render_template_string, redirect, url_for, session

app = Flask(__name__)
app.secret_key = "super_secret_key_change_me"

def get_db():
    conn = sqlite3.connect("final_challenge.db")
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
        is_admin INTEGER,
        bio TEXT
    )
    """)

    cursor.execute("DELETE FROM users")
    cursor.execute("INSERT INTO users (username, password, is_admin, bio) VALUES ('admin', 'adminpass999', 1, 'System Administrator')")
    cursor.execute("INSERT INTO users (username, password, is_admin, bio) VALUES ('student', 'student123', 0, 'Regular student account')")
    conn.commit()
    conn.close()

@app.route("/")
def index():
    if "user_id" in session:
        return f"<h1>Welcome {session['username']}</h1><a href='/profile?id={session['user_id']}'>View Profile</a> | <a href='/logout'>Logout</a>"
    return '<h1>Home Page</h1><a href="/login">Login</a>'

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        conn = get_db()
        cursor = conn.cursor()
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        try:
            cursor.execute(query)
            user = cursor.fetchone()
        except:
            user = None

        if user:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["is_admin"] = user["is_admin"]
            return redirect(url_for("index"))

        return "Invalid Credentials", 401

    return '''
    <form method="post">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <input type="submit" value="Login">
    </form>
    '''

@app.route("/profile")
def profile():
    user_id = request.args.get("id")
    if not user_id:
        return "Missing ID", 400

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(f"SELECT username, bio, is_admin FROM users WHERE id = {user_id}")
    user = cursor.fetchone()
    conn.close()

    if user:
        template = f"<h1>Profile of {user['username']}</h1><p>Bio: {user['bio']}</p>"
        if user["is_admin"]:
            template += "<p>FLAG: FLAG{FINAL_CHALLENGE_MASTER_2026}</p>"
        return render_template_string(template)

    return "User not found", 404

@app.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return "No file part", 400

    file = request.files["file"]

    if file.filename == "":
        return "No selected file", 400

    upload_folder = "uploads"
    os.makedirs(upload_folder, exist_ok=True)
    file.save(os.path.join(upload_folder, file.filename))

    return f"File uploaded successfully: {file.filename}"

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5000)
