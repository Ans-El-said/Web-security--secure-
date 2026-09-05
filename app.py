from flask import Flask, request, render_template, redirect, session, send_from_directory, abort
from werkzeug.security import generate_password_hash, check_password_hash
import subprocess
import requests
import os
import secrets
import ipaddress
import socket
from urllib.parse import urlparse
from database import get_db, init_db

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False
)

def is_safe_url(url):
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return False
        if parsed.username or parsed.password:
            return False
        host = parsed.hostname
        try:
            addresses = [ipaddress.ip_address(host)]
        except ValueError:
            addresses = [
                ipaddress.ip_address(info[4][0])
                for info in socket.getaddrinfo(host, None)
            ]
        return all(not ip.is_private and not ip.is_loopback and not ip.is_link_local and not ip.is_reserved for ip in addresses)
    except (ValueError, socket.gaierror):
        return False

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    message = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        email = request.form.get("email", "").strip()
        if not username or not password or not email:
            message = "All fields are required."
        else:
            db = get_db()
            try:
                db.execute(
                    "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
                    (username, generate_password_hash(password), email)
                )
                db.commit()
                message = "Account created successfully."
            except Exception:
                message = "Unable to create account."
            finally:
                db.close()
    return render_template("register.html", message=message)

@app.route("/login", methods=["GET", "POST"])
def login():
    message = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()
        db.close()
        if user and check_password_hash(user["password"], password):
            session.clear()
            session["username"] = user["username"]
            return redirect("/dashboard")
        message = "Invalid username or password."
    return render_template("login.html", message=message)

@app.route("/change-email", methods=["GET", "POST"])
def change_email():
    if "username" not in session:
        return redirect("/login")
    message = ""
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        db = get_db()
        db.execute(
            "UPDATE users SET email = ? WHERE username = ?",
            (email, session["username"])
        )
        db.commit()
        db.close()
        message = "Email changed successfully."
    return render_template("change_email.html", message=message)

@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect("/login")
    db = get_db()
    tickets = db.execute("SELECT * FROM tickets").fetchall()
    db.close()
    return render_template(
        "dashboard.html",
        username=session["username"],
        tickets=tickets
    )

@app.route("/download")
def download():
    if "username" not in session:
        return redirect("/login")
    filename = request.args.get("file", "")
    if not filename or os.path.basename(filename) != filename:
        abort(400)
    return send_from_directory(
        os.path.join(app.root_path, "files"),
        filename,
        as_attachment=True
    )

@app.route("/debug-info")
def debug_info():
    return {
        "app": "Support Portal",
        "environment": "production"
    }

@app.route("/search")
def search():
    search_term = request.args.get("q", "")
    db = get_db()
    pattern = f"%{search_term}%"
    tickets = db.execute(
        "SELECT * FROM tickets WHERE title LIKE ? OR description LIKE ?",
        (pattern, pattern)
    ).fetchall()
    db.close()
    return render_template(
        "search.html",
        search_term=search_term,
        tickets=tickets
    )

@app.route("/ping")
def ping():
    host = request.args.get("host", "").strip()
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return "Invalid host", 400
    try:
        result = subprocess.run(
            ["ping", "-c", "1", host],
            capture_output=True,
            text=True,
            timeout=5,
            check=False
        )
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return "Request timed out", 504

@app.route("/csrf")
def csrf():
    return render_template("csrf.html")

@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    if not url:
        return "Missing URL", 400
    if not is_safe_url(url):
        return "Invalid URL", 400
    try:
        response = requests.get(url, timeout=5, allow_redirects=False)
        response.raise_for_status()
        return response.text[:1000000]
    except requests.RequestException:
        return "Unable to fetch URL", 502

@app.route("/ssti")
def ssti():
    name = request.args.get("name", "")
    return render_template("ssti.html", name=name)

if __name__ == "__main__":
    init_db()
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
