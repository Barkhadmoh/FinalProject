from flask import Flask, request, jsonify
import jwt
import datetime
import json
import os
import logging
from flask_bcrypt import Bcrypt
from functools import wraps

app = Flask(__name__)
bcrypt = Bcrypt(app)

# ── Settings ──────────────────────────────────────────────
SECRET_KEY = "finalproject_secret_key"
USERS_FILE = "users.json"
TOKEN_BLACKLIST = set()

# ── Brute Force Protection ─────────────────────────────────
FAILED_ATTEMPTS = {}
MAX_ATTEMPTS = 5
BLOCKED_USERS = set()

# ── Security Logging ───────────────────────────────────────
logging.basicConfig(
    filename="security.log",
    level=logging.WARNING,
    format="%(asctime)s - %(message)s"
)

# ── Helper Functions ───────────────────────────────────────
def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r") as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)

# ── Token Validation ───────────────────────────────────────
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
        if not token:
            logging.warning(f"ATTACK: No token on route: {request.path}")
            return jsonify({"error": "Token is missing!"}), 401
        if token in TOKEN_BLACKLIST:
            return jsonify({"error": "Token revoked. Please login again."}), 401
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            request.current_user = data
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired!"}), 401
        except jwt.InvalidTokenError:
            logging.warning(f"ATTACK: Invalid/tampered token on route: {request.path}")
            return jsonify({"error": "Invalid token!"}), 401
        return f(*args, **kwargs)
    return decorated

# ── Admin Check ────────────────────────────────────────────
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = request.current_user
        if user.get("role") != "admin":
            logging.warning(
                f"ATTACK: 403 FORBIDDEN - '{user.get('username')}' tried {request.path}"
            )
            return jsonify({"error": "Access denied! Admins only."}), 403
        return f(*args, **kwargs)
    return decorated

# ══════════════════════════════════════════════════
# REGISTER — With Input Validation
# ══════════════════════════════════════════════════
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided!"}), 400
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    role = data.get("role", "user")
    if not username or not password:
        return jsonify({"error": "Username and password cannot be empty!"}), 400
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters!"}), 400
    users = load_users()
    if username in users:
        return jsonify({"error": "User already exists!"}), 409
    hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")
    users[username] = {"password": hashed_pw, "role": role}
    save_users(users)
    return jsonify({"message": f"User '{username}' registered successfully!"}), 201

# ══════════════════════════════════════════════════
# LOGIN — With Brute Force Protection
# ══════════════════════════════════════════════════
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided!"}), 400
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    if not username or not password:
        return jsonify({"error": "Username and password cannot be empty!"}), 400

    # Brute Force Check
    if username in BLOCKED_USERS:
        logging.warning(f"ATTACK: Blocked user '{username}' tried to login")
        return jsonify({"error": "Account locked! Too many failed attempts."}), 403

    users = load_users()
    if username not in users:
        return jsonify({"error": "Wrong username or password"}), 401

    user = users[username]
    if not bcrypt.check_password_hash(user["password"], password):
        FAILED_ATTEMPTS[username] = FAILED_ATTEMPTS.get(username, 0) + 1
        attempts_left = MAX_ATTEMPTS - FAILED_ATTEMPTS[username]
        logging.warning(f"ATTACK: Failed login for '{username}' attempt {FAILED_ATTEMPTS[username]}")
        if FAILED_ATTEMPTS[username] >= MAX_ATTEMPTS:
            BLOCKED_USERS.add(username)
            logging.warning(f"SECURITY: Account '{username}' LOCKED!")
            return jsonify({"error": "Account locked! Too many failed attempts."}), 403
        return jsonify({"error": f"Wrong password! {attempts_left} attempts left before lockout."}), 401

    FAILED_ATTEMPTS.pop(username, None)
    token = jwt.encode({
        "username": username,
        "role": user["role"],
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }, SECRET_KEY, algorithm="HS256")
    return jsonify({"token": token}), 200

# ══════════════════════════════════════════════════
# LOGOUT — Token Blacklisting
# ══════════════════════════════════════════════════
@app.route("/logout", methods=["POST"])
@token_required
def logout():
    token = request.headers.get("Authorization").split(" ")[1]
    TOKEN_BLACKLIST.add(token)
    return jsonify({"message": "Logged out! Token is now invalid."}), 200

# ══════════════════════════════════════════════════
# PROFILE — User + Admin
# ══════════════════════════════════════════════════
@app.route("/profile", methods=["GET"])
@token_required
def profile():
    user = request.current_user
    return jsonify({
        "message": f"Hello {user['username']}! Welcome.",
        "role": user["role"]
    }), 200

# ══════════════════════════════════════════════════
# DELETE USER — Admin Only
# ══════════════════════════════════════════════════
@app.route("/user/<user_id>", methods=["DELETE"])
@token_required
@admin_required
def delete_user(user_id):
    users = load_users()
    if user_id not in users:
        return jsonify({"error": "User not found!"}), 404
    del users[user_id]
    save_users(users)
    return jsonify({"message": f"User '{user_id}' deleted."}), 200

# ── Start ──────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=True)