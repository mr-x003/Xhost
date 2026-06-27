import os
import json
import re
import shutil
import socket
import hashlib
import subprocess
import threading
import time
import sys
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta

import psutil
from flask import Flask, send_from_directory, request, jsonify, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ✅ NEW: per-user root
USERS_ROOT = os.path.join(BASE_DIR, "USERS")
DATA_DIR = os.path.join(BASE_DIR, "DATA")
USERS_DB = os.path.join(DATA_DIR, "users.json")
VERIFICATION_CODES = os.path.join(DATA_DIR, "verification_codes.json")

os.makedirs(USERS_ROOT, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("PANEL_SECRET_KEY", "CHANGE_ME_" + os.urandom(16).hex())

ADMIN_USERNAME = os.environ.get("ADMIN_USER", "Mrx")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASS", "Asdfghjkl.0")

# SMTP Configuration
SMTP_ENABLED = os.environ.get("SMTP_ENABLED", "false").lower() == "true"
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", 587))
SMTP_USER = os.environ.get("SMTP_USER", "xhostverify@gmail.com")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "sbltyvdzibrsyztj")
SMTP_FROM = os.environ.get("SMTP_FROM", SMTP_USER)

running_procs = {}   # key -> (Popen, log_file_handle)
server_states = {}   # key -> Offline/Installing/Starting/Running/Banned
lock = threading.Lock()

# Store active user sessions to force logout
active_sessions = {}  # username -> session_id


def get_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def sanitize_folder_name(name: str) -> str:
    name = (name or "").strip()
    name = re.sub(r"\s+", "-", name)
    name = re.sub(r"[^A-Za-z0-9\-_\.]", "", name)
    return name[:200]


def safe_name(name: str) -> str:
    name = (name or "").strip()
    name = re.sub(r"[\\/]+", "", name)
    name = re.sub(r"[^A-Za-z0-9\-_\. ]", "", name)
    return name[:200].strip()


def set_state(key: str, state: str):
    with lock:
        server_states[key] = state


def get_state(key: str) -> str:
    with lock:
        return server_states.get(key, "Offline")


def log_append(key: str, text: str):
    try:
        owner, folder = parse_server_key(key, allow_admin=True)
        p = os.path.join(get_server_dir(owner, folder), "server.log")
        with open(p, "a", encoding="utf-8", errors="ignore") as f:
            f.write(text)
    except Exception:
        pass


# ---------------------------
# Verification Codes
# ---------------------------
def load_verification_codes():
    if not os.path.exists(VERIFICATION_CODES):
        return {}
    try:
        with open(VERIFICATION_CODES, "r", encoding="utf-8") as f:
            return json.load(f) or {}
    except Exception:
        return {}


def save_verification_codes(codes):
    tmp = VERIFICATION_CODES + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(codes, f, indent=2)
    os.replace(tmp, VERIFICATION_CODES)


def generate_verification_code():
    return str(secrets.randbelow(900000) + 100000)  # 6-digit code


def send_verification_email(email, code):
    if not SMTP_ENABLED:
        print(f"[SMTP] Verification code for {email}: {code}")
        return True
    
    try:
        msg = MIMEMultipart()
        msg['From'] = SMTP_FROM
        msg['To'] = email
        msg['Subject'] = "Verify Your Account - X Panel"
        
        body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background: #f5f5f5;">
            <div style="background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                <h2 style="color: #00d4ff; margin-top: 0;">Welcome to X Panel!</h2>
                <p style="color: #333; font-size: 16px;">Thank you for registering. Please verify your email address using the code below:</p>
                
                <div style="background: #f0f7ff; padding: 20px; border-radius: 8px; text-align: center; margin: 20px 0;">
                    <h1 style="color: #00d4ff; font-size: 48px; letter-spacing: 10px; margin: 0;">{code}</h1>
                </div>
                
                <p style="color: #666; font-size: 14px;">This code will expire in <strong>10 minutes</strong>.</p>
                
                <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
                
                <p style="color: #999; font-size: 12px;">If you didn't request this, please ignore this email.</p>
                <p style="color: #999; font-size: 12px;">© 2024 X Panel. All rights reserved.</p>
            </div>
        </body>
        </html>
        """
        
        msg.attach(MIMEText(body, 'html'))
        
        server = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"[SMTP] Error sending email: {e}")
        return False


# ---------------------------
# Users DB
# ---------------------------
def load_users():
    if not os.path.exists(USERS_DB):
        return {"users": []}
    try:
        with open(USERS_DB, "r", encoding="utf-8") as f:
            return json.load(f) or {"users": []}
    except Exception:
        return {"users": []}


def save_users(db):
    tmp = USERS_DB + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2)
    os.replace(tmp, USERS_DB)


def find_user(db, username: str):
    u = (username or "").strip().lower()
    for x in db.get("users", []):
        if (x.get("username") or "").strip().lower() == u:
            return x
    return None


def is_admin_session():
    u = session.get("user") or {}
    return bool(u.get("is_admin"))


def current_username():
    u = session.get("user") or {}
    return (u.get("username") or "").strip()


def get_session_id():
    return session.get("session_id", "")


def get_user_limit(username: str) -> int:
    if is_admin_session():
        return 999999
    db = load_users()
    u = find_user(db, username)
    if not u:
        return 1
    return 5 if u.get("premium", False) else 1


# ---------------------------
# Auth decorators
# ---------------------------
def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user"):
            return redirect("/login")
        
        # Check if user is still active (not banned)
        username = current_username()
        if username:
            db = load_users()
            u = find_user(db, username)
            if u and not u.get("active", True):
                session.clear()
                return redirect("/login?banned=true")
        
        return fn(*args, **kwargs)
    return wrapper


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user"):
            return redirect("/login")
        if not is_admin_session():
            return jsonify({"success": False, "message": "Admin only"}), 403
        return fn(*args, **kwargs)
    return wrapper


# ---------------------------
# Per-user server directories
# ---------------------------
def get_user_servers_root(username: str) -> str:
    return os.path.join(USERS_ROOT, username, "servers")


def get_server_dir(owner: str, folder: str) -> str:
    return os.path.join(get_user_servers_root(owner), folder)


def ensure_user_dirs(username: str):
    os.makedirs(get_user_servers_root(username), exist_ok=True)


def parse_server_key(key: str, allow_admin: bool):
    """
    key formats:
      - normal user:  "serverFolder"
      - admin:        "username::serverFolder"
    """
    key = (key or "").strip()

    if "::" in key:
        owner, folder = key.split("::", 1)
        owner = owner.strip()
        folder = folder.strip()

        if not allow_admin:
            raise ValueError("not allowed")

        if not is_admin_session():
            raise ValueError("forbidden")
        return owner, folder

    # no owner provided -> current user
    return current_username(), key


def can_access_key(key: str) -> bool:
    try:
        owner, folder = parse_server_key(key, allow_admin=True)
    except Exception:
        return False
    if is_admin_session():
        return True
    return owner == current_username()


def safe_join_server_path(key: str, rel_path: str = "") -> str:
    owner, folder = parse_server_key(key, allow_admin=True)

    root = os.path.abspath(get_server_dir(owner, folder))
    rel_path = (rel_path or "").replace("\\", "/").strip()
    if rel_path.startswith("/") or rel_path.startswith("~"):
        rel_path = rel_path.lstrip("/").lstrip("~")

    # Prevent path traversal
    if ".." in rel_path:
        raise ValueError("Invalid path")

    joined = os.path.abspath(os.path.join(root, rel_path))
    if not (joined == root or joined.startswith(root + os.sep)):
        raise ValueError("Invalid path")
    return joined


# ---------------------------
# Meta per server
# ---------------------------
def ensure_meta(owner: str, folder: str):
    server_dir = get_server_dir(owner, folder)
    os.makedirs(server_dir, exist_ok=True)
    meta_path = os.path.join(server_dir, "meta.json")
    base = {"display_name": folder, "startup_file": "", "owner": owner, "banned": False}
    if not os.path.exists(meta_path):
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(base, f, indent=2)
    else:
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                m = json.load(f) or {}
        except Exception:
            m = {}
        changed = False
        for k, v in base.items():
            if k not in m:
                m[k] = v
                changed = True
        if m.get("owner") != owner:
            m["owner"] = owner
            changed = True
        if changed:
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump(m, f, indent=2)
    return meta_path


def read_meta(owner: str, folder: str):
    meta_path = ensure_meta(owner, folder)
    try:
        with open(meta_path, "r", encoding="utf-8") as f:
            return json.load(f) or {}
    except Exception:
        return {"display_name": folder, "startup_file": "", "owner": owner, "banned": False}


def write_meta(owner: str, folder: str, meta):
    meta_path = ensure_meta(owner, folder)
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)


# ---------------------------
# Auto-install system
# ---------------------------
def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def installed_file_path(owner: str, folder: str):
    return os.path.join(get_server_dir(owner, folder), ".installed")


def read_installed(owner: str, folder: str):
    p = installed_file_path(owner, folder)
    data = {"req_sha": "", "pkgs": set()}
    if not os.path.exists(p):
        return data
    try:
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            for line in f.read().splitlines():
                line = line.strip()
                if not line:
                    continue
                if line.startswith("REQ_SHA="):
                    data["req_sha"] = line.split("=", 1)[1].strip()
                else:
                    data["pkgs"].add(line)
    except Exception:
        pass
    return data


def write_installed(owner: str, folder: str, req_sha=None, add_pkgs=None):
    p = installed_file_path(owner, folder)
    cur = read_installed(owner, folder)
    if req_sha is not None:
        cur["req_sha"] = req_sha
    if add_pkgs:
        cur["pkgs"].update(add_pkgs)
    lines = []
    if cur["req_sha"]:
        lines.append(f"REQ_SHA={cur['req_sha']}")
    lines.extend(sorted(cur["pkgs"]))
    with open(p, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + ("\n" if lines else ""))


def ensure_requirements_installed(owner: str, folder: str):
    server_dir = get_server_dir(owner, folder)
    req_path = os.path.join(server_dir, "requirements.txt")
    if not os.path.exists(req_path):
        return False

    req_sha = sha256_file(req_path)
    cur = read_installed(owner, folder)
    if cur["req_sha"] == req_sha:
        return False

    log_append(f"{owner}::{folder}", "[SYSTEM] Installing requirements.txt...\n")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], cwd=server_dir)
        write_installed(owner, folder, req_sha=req_sha)
        log_append(f"{owner}::{folder}", "[SYSTEM] requirements installed ✅\n")
        return True
    except subprocess.CalledProcessError as e:
        log_append(f"{owner}::{folder}", f"[SYSTEM] requirements install failed: {e}\n")
        return False


def start_with_autoinstall(owner: str, folder: str, startup_file: str):
    wrapper_code = r'''
import runpy, sys, subprocess, traceback, re, os
script = sys.argv[1]
cwd = os.getcwd()

def append_installed(pkg):
    try:
        p = os.path.join(cwd, ".installed")
        existing = set()
        if os.path.exists(p):
            with open(p, "r", encoding="utf-8", errors="ignore") as f:
                existing = set([x.strip() for x in f.read().splitlines() if x.strip()])
        if pkg and pkg not in existing:
            with open(p, "a", encoding="utf-8") as f:
                f.write(pkg + "\n")
    except:
        pass

def parse_missing_name(e):
    n = getattr(e, "name", None)
    if n: return n
    s = str(e)
    m = re.search(r"No module named '([^']+)'", s)
    if m: return m.group(1)
    return None

while True:
    try:
        runpy.run_path(script, run_name="__main__")
        break
    except ModuleNotFoundError as e:
        pkg = parse_missing_name(e)
        if not pkg:
            traceback.print_exc()
            break
        print(f"[AUTO-INSTALL] Missing module: {pkg} -> installing...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])
            append_installed(pkg)
            print(f"[AUTO-INSTALL] Installed: {pkg} ✅ -> restarting...")
            continue
        except Exception as ex:
            print(f"[AUTO-INSTALL] Failed: {ex}")
            traceback.print_exc()
            break
    except Exception:
        traceback.print_exc()
        break
'''
    server_dir = get_server_dir(owner, folder)
    log_path = os.path.join(server_dir, "server.log")
    log_file = open(log_path, "a", encoding="utf-8", errors="ignore")

    proc = subprocess.Popen(
        [sys.executable, "-u", "-c", wrapper_code, startup_file],
        cwd=server_dir,
        stdout=log_file,
        stderr=log_file,
    )
    return proc, log_file


def stop_proc(key: str):
    if key in running_procs:
        proc, logf = running_procs[key]
        try:
            p = psutil.Process(proc.pid)
            for child in p.children(recursive=True):
                child.kill()
            p.kill()
        except Exception:
            pass
        try:
            logf.close()
        except Exception:
            pass
        running_procs.pop(key, None)


# ---------------------------
# Pages
# ---------------------------
@app.route("/")
@login_required
def home():
    return send_from_directory(BASE_DIR, "index.html")


@app.route("/login")
def login_page():
    return send_from_directory(BASE_DIR, "login.html")


@app.route("/create")
def create_page():
    return send_from_directory(BASE_DIR, "create.html")


@app.route("/verify")
def verify_page():
    return send_from_directory(BASE_DIR, "verify.html")


@app.route("/admin")
@login_required
def admin_page():
    if not is_admin_session():
        return redirect("/")
    return send_from_directory(BASE_DIR, "admin.html")


@app.route("/logout")
def logout():
    session.pop("user", None)
    session.pop("session_id", None)
    return redirect("/login")


# ---------------------------
# Auth APIs
# ---------------------------
@app.route("/api/auth/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        session_id = secrets.token_hex(16)
        session["user"] = {"username": ADMIN_USERNAME, "is_admin": True}
        session["session_id"] = session_id
        return jsonify({"success": True, "is_admin": True})

    db = load_users()
    u = find_user(db, username)
    if not u:
        return jsonify({"success": False, "message": "Invalid username or password"}), 401
    if not u.get("active", True):
        return jsonify({"success": False, "message": "Account is banned / inactive"}), 403
    if not u.get("verified", False):
        return jsonify({"success": False, "message": "Account not verified. Please check your email."}), 403
    if not check_password_hash(u.get("password_hash", ""), password):
        return jsonify({"success": False, "message": "Invalid username or password"}), 401

    session_id = secrets.token_hex(16)
    session["user"] = {"username": u.get("username"), "is_admin": False}
    session["session_id"] = session_id
    ensure_user_dirs(u.get("username"))
    return jsonify({"success": True, "is_admin": False})


@app.route("/api/auth/create", methods=["POST"])
def api_create():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip()
    password = data.get("password") or ""
    password2 = data.get("password2") or ""

    if not username or len(username) < 3:
        return jsonify({"success": False, "message": "Username must be at least 3 chars"}), 400
    if not re.fullmatch(r"[A-Za-z0-9_\.]+", username):
        return jsonify({"success": False, "message": "Username allowed: letters, numbers, _ and ."}), 400
    if username.upper() == ADMIN_USERNAME.upper():
        return jsonify({"success": False, "message": "This username is reserved"}), 400
    if not email or "@" not in email:
        return jsonify({"success": False, "message": "Enter a valid email"}), 400
    if len(password) < 6:
        return jsonify({"success": False, "message": "Password must be at least 6 chars"}), 400
    if password != password2:
        return jsonify({"success": False, "message": "Passwords do not match"}), 400

    db = load_users()
    if find_user(db, username):
        return jsonify({"success": False, "message": "Username already exists"}), 409
    
    # Check if email already used
    for u in db.get("users", []):
        if u.get("email", "").lower() == email.lower():
            return jsonify({"success": False, "message": "Email already registered"}), 409

    # Generate verification code
    code = generate_verification_code()
    
    # Send verification email
    if SMTP_ENABLED:
        if not send_verification_email(email, code):
            return jsonify({"success": False, "message": "Failed to send verification email. Please try again."}), 500
    
    # Store user with unverified status
    db["users"].append({
        "username": username,
        "email": email,
        "password_hash": generate_password_hash(password),
        "active": True,
        "premium": False,
        "verified": False,
        "created_at": datetime.now().isoformat()
    })
    save_users(db)
    ensure_user_dirs(username)
    
    # Store verification code
    codes = load_verification_codes()
    codes[username] = {
        "code": code,
        "email": email,
        "expires": (datetime.now() + timedelta(minutes=10)).isoformat()
    }
    save_verification_codes(codes)
    
    return jsonify({"success": True, "requires_verification": True, "username": username})


@app.route("/api/auth/verify", methods=["POST"])
def api_verify():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    code = (data.get("code") or "").strip()
    
    if not username or not code:
        return jsonify({"success": False, "message": "Username and code required"}), 400
    
    codes = load_verification_codes()
    if username not in codes:
        return jsonify({"success": False, "message": "Invalid verification request"}), 400
    
    stored = codes[username]
    if stored.get("code") != code:
        return jsonify({"success": False, "message": "Invalid verification code"}), 400
    
    expires = datetime.fromisoformat(stored.get("expires", datetime.now().isoformat()))
    if datetime.now() > expires:
        return jsonify({"success": False, "message": "Verification code expired. Please request a new one."}), 400
    
    # Verify user
    db = load_users()
    u = find_user(db, username)
    if u:
        u["verified"] = True
        save_users(db)
    
    # Remove verification code
    del codes[username]
    save_verification_codes(codes)
    
    return jsonify({"success": True, "message": "Account verified successfully!"})


@app.route("/api/auth/resend-verification", methods=["POST"])
def api_resend_verification():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    
    if not username:
        return jsonify({"success": False, "message": "Username required"}), 400
    
    db = load_users()
    u = find_user(db, username)
    if not u:
        return jsonify({"success": False, "message": "User not found"}), 404
    
    if u.get("verified", False):
        return jsonify({"success": False, "message": "Account already verified"}), 400
    
    code = generate_verification_code()
    email = u.get("email", "")
    
    if SMTP_ENABLED:
        if not send_verification_email(email, code):
            return jsonify({"success": False, "message": "Failed to send email"}), 500
    
    codes = load_verification_codes()
    codes[username] = {
        "code": code,
        "email": email,
        "expires": (datetime.now() + timedelta(minutes=10)).isoformat()
    }
    save_verification_codes(codes)
    
    return jsonify({"success": True, "message": "Verification code resent!"})


# ---------------------------
# Server listing (per-user) + admin sees all
# ---------------------------
def list_all_servers_for_admin():
    servers = []
    if not os.path.isdir(USERS_ROOT):
        return servers

    for owner in sorted(os.listdir(USERS_ROOT)):
        root = get_user_servers_root(owner)
        if not os.path.isdir(root):
            continue
        for folder in sorted(os.listdir(root)):
            server_dir = get_server_dir(owner, folder)
            if not os.path.isdir(server_dir):
                continue
            meta = read_meta(owner, folder)
            banned = bool(meta.get("banned", False))
            key = f"{owner}::{folder}"
            st = "Banned" if banned else get_state(key)
            servers.append({
                "title": meta.get("display_name", folder),
                "folder": folder,
                "owner": owner,
                "key": key,
                "subtitle": f"Owner: {owner}",
                "startup_file": meta.get("startup_file", ""),
                "status": st,
                "banned": banned
            })
    return servers


def list_servers_for_user(username: str):
    ensure_user_dirs(username)
    root = get_user_servers_root(username)
    servers = []
    for folder in sorted(os.listdir(root)):
        server_dir = get_server_dir(username, folder)
        if not os.path.isdir(server_dir):
            continue
        meta = read_meta(username, folder)
        banned = bool(meta.get("banned", False))
        key = folder  # user only uses folder
        st = "Banned" if banned else get_state(key)
        servers.append({
            "title": meta.get("display_name", folder),
            "folder": folder,
            "owner": username,
            "key": key,
            "subtitle": f"Owner: {username}",
            "startup_file": meta.get("startup_file", ""),
            "status": st,
            "banned": banned
        })
    return servers


@app.route("/servers")
@login_required
def servers():
    if is_admin_session():
        return jsonify({"success": True, "servers": list_all_servers_for_admin()})
    return jsonify({"success": True, "servers": list_servers_for_user(current_username())})


@app.route("/add", methods=["POST"])
@login_required
def add_server():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    folder = sanitize_folder_name(name)
    if not folder:
        return jsonify({"success": False, "message": "Invalid server name"}), 400

    if is_admin_session():
        owner = current_username()
    else:
        owner = current_username()

    ensure_user_dirs(owner)

    # enforce limits for non-admin
    if not is_admin_session():
        limit = get_user_limit(owner)
        existing = [d for d in os.listdir(get_user_servers_root(owner)) if os.path.isdir(get_server_dir(owner, d))]
        if len(existing) >= limit:
            return jsonify({"success": False, "message": f"Server limit reached ({limit}). Ask admin for premium."}), 403

    target = get_server_dir(owner, folder)
    if os.path.exists(target):
        return jsonify({"success": False, "message": "Server already exists"}), 409

    os.makedirs(target, exist_ok=True)
    open(os.path.join(target, "server.log"), "w", encoding="utf-8").close()

    meta = {
        "display_name": name or folder,
        "startup_file": "",
        "owner": owner,
        "banned": False
    }
    write_meta(owner, folder, meta)

    set_state(folder if not is_admin_session() else f"{owner}::{folder}", "Offline")

    if is_admin_session():
        return jsonify({"success": True, "servers": list_all_servers_for_admin()})
    return jsonify({"success": True, "servers": list_servers_for_user(owner)})


# ---------------------------
# Server control + stats
# ---------------------------
@app.route("/server/stats/<path:key>")
@login_required
def server_stats(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403

    owner, folder = parse_server_key(key, allow_admin=True)
    server_dir = get_server_dir(owner, folder)
    if not os.path.isdir(server_dir):
        return jsonify({"status": "Offline", "cpu": "0%", "mem": "0 MB", "logs": "", "ip": get_ip()}), 404

    meta = read_meta(owner, folder)
    if meta.get("banned", False):
        set_state(key, "Banned")

    proc_tuple = running_procs.get(key)
    running = False
    cpu, mem = "0%", "0 MB"

    if proc_tuple:
        proc, _logf = proc_tuple
        if psutil.pid_exists(proc.pid):
            try:
                p = psutil.Process(proc.pid)
                if p.is_running() and p.status() != psutil.STATUS_ZOMBIE:
                    running = True
                    cpu = f"{p.cpu_percent(interval=None)}%"
                    mem = f"{p.memory_info().rss / 1024 / 1024:.1f} MB"
            except Exception:
                pass

    log_path = os.path.join(server_dir, "server.log")
    try:
        logs = open(log_path, "r", encoding="utf-8", errors="ignore").read() if os.path.exists(log_path) else ""
    except Exception:
        logs = ""

    state = get_state(key)
    if meta.get("banned", False):
        state = "Banned"
    elif running:
        state = "Running"
        set_state(key, "Running")
    elif state not in ("Installing", "Starting"):
        state = "Offline"
        set_state(key, "Offline")

    return jsonify({"status": state, "cpu": cpu, "mem": mem, "logs": logs, "ip": get_ip()})


def background_start(key: str, owner: str, folder: str, startup_file: str):
    try:
        set_state(key, "Installing")
        log_append(key, "[SYSTEM] Preparing...\n")

        ensure_requirements_installed(owner, folder)

        set_state(key, "Starting")
        log_append(key, "[SYSTEM] Starting...\n")

        proc, logf = start_with_autoinstall(owner, folder, startup_file)
        running_procs[key] = (proc, logf)

        time.sleep(1.0)
        if proc.poll() is None:
            set_state(key, "Running")
        else:
            set_state(key, "Offline")
    except Exception as e:
        log_append(key, f"[SYSTEM] Start failed: {e}\n")
        set_state(key, "Offline")


@app.route("/server/action/<path:key>/<act>", methods=["POST"])
@login_required
def server_action(key, act):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403

    owner, folder = parse_server_key(key, allow_admin=True)
    server_dir = get_server_dir(owner, folder)
    if not os.path.isdir(server_dir):
        return jsonify({"success": False, "message": "Server not found"}), 404

    meta = read_meta(owner, folder)
    if meta.get("banned", False):
        set_state(key, "Banned")
        return jsonify({"success": False, "message": "Server is banned by admin"}), 403

    if act in ("stop", "restart"):
        stop_proc(key)
        set_state(key, "Offline")

    if act == "stop":
        return jsonify({"success": True})

    startup = meta.get("startup_file") or ""
    if not startup:
        return jsonify({"success": False, "message": "No main file set"}), 400

    open(os.path.join(server_dir, "server.log"), "w", encoding="utf-8").close()

    t = threading.Thread(target=background_start, args=(key, owner, folder, startup), daemon=True)
    t.start()
    return jsonify({"success": True})


@app.route("/server/set-startup/<path:key>", methods=["POST"])
@login_required
def set_startup(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403

    owner, folder = parse_server_key(key, allow_admin=True)
    server_dir = get_server_dir(owner, folder)
    if not os.path.isdir(server_dir):
        return jsonify({"success": False, "message": "Server not found"}), 404

    data = request.get_json(silent=True) or {}
    f = (data.get("file") or "").strip()
    meta = read_meta(owner, folder)
    meta["startup_file"] = f
    write_meta(owner, folder, meta)
    return jsonify({"success": True})


# ---------------------------
# File manager APIs (FIXED)
# ---------------------------
@app.route("/files/list/<path:key>")
@login_required
def files_list(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden", "path": ""}), 403

    rel = request.args.get("path", "") or ""
    try:
        base = safe_join_server_path(key, rel)
    except Exception as e:
        return jsonify({"success": False, "message": str(e), "path": ""}), 400

    dirs, files = [], []
    if os.path.isdir(base):
        for name in sorted(os.listdir(base), key=lambda x: (not os.path.isdir(os.path.join(base, x)), x.lower())):
            if rel == "" and name in ("meta.json", "server.log"):
                continue
            full = os.path.join(base, name)
            if os.path.isdir(full):
                dirs.append({"name": name})
            elif os.path.isfile(full):
                try:
                    size_kb = os.path.getsize(full) / 1024
                    size = f"{size_kb:.1f} KB"
                except Exception:
                    size = ""
                files.append({"name": name, "size": size})

    return jsonify({"success": True, "path": rel, "dirs": dirs, "files": files})


@app.route("/files/content/<path:key>")
@login_required
def file_content(key):
    if not can_access_key(key):
        return jsonify({"content": ""}), 403
    file_rel = request.args.get("file", "") or ""
    try:
        full = safe_join_server_path(key, file_rel)
    except Exception:
        return jsonify({"content": ""}), 400
    if os.path.isdir(full):
        return jsonify({"content": ""}), 400
    try:
        with open(full, "r", encoding="utf-8", errors="ignore") as f:
            return jsonify({"content": f.read()})
    except Exception:
        return jsonify({"content": ""})


@app.route("/files/save/<path:key>", methods=["POST"])
@login_required
def file_save(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403

    data = request.get_json(silent=True) or {}
    file_rel = data.get("file", "") or ""
    content = data.get("content", "")

    try:
        full = safe_join_server_path(key, file_rel)
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 400

    os.makedirs(os.path.dirname(full), exist_ok=True)
    try:
        with open(full, "w", encoding="utf-8") as f:
            f.write(content)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/files/mkdir/<path:key>", methods=["POST"])
@login_required
def file_mkdir(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403
    data = request.get_json(silent=True) or {}
    rel = data.get("path", "") or ""
    name = safe_name(data.get("name", ""))
    if not name:
        return jsonify({"success": False, "message": "Bad name"}), 400
    try:
        target = safe_join_server_path(key, os.path.join(rel, name))
        # Check if path is within server directory
        owner, folder = parse_server_key(key, allow_admin=True)
        server_dir = get_server_dir(owner, folder)
        if not target.startswith(server_dir + os.sep) and target != server_dir:
            return jsonify({"success": False, "message": "Invalid path"}), 400
        os.makedirs(target, exist_ok=False)
        return jsonify({"success": True})
    except FileExistsError:
        return jsonify({"success": False, "message": "Already exists"}), 409
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/files/rename/<path:key>", methods=["POST"])
@login_required
def file_rename(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403
    data = request.get_json(silent=True) or {}
    rel = data.get("path", "") or ""
    old = safe_name(data.get("old", ""))
    new = safe_name(data.get("new", ""))
    if not old or not new:
        return jsonify({"success": False, "message": "Both old and new names required"}), 400
    if old == new:
        return jsonify({"success": True})  # No change needed
    try:
        src = safe_join_server_path(key, os.path.join(rel, old))
        dst = safe_join_server_path(key, os.path.join(rel, new))
        
        # Check if source exists
        if not os.path.exists(src):
            return jsonify({"success": False, "message": "Source does not exist"}), 404
        
        # Check if destination already exists
        if os.path.exists(dst):
            return jsonify({"success": False, "message": "Destination already exists"}), 409
        
        # Check if within server directory
        owner, folder = parse_server_key(key, allow_admin=True)
        server_dir = get_server_dir(owner, folder)
        if not src.startswith(server_dir + os.sep) and src != server_dir:
            return jsonify({"success": False, "message": "Invalid source path"}), 400
        if not dst.startswith(server_dir + os.sep) and dst != server_dir:
            return jsonify({"success": False, "message": "Invalid destination path"}), 400
        
        os.rename(src, dst)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/files/delete/<path:key>", methods=["POST"])
@login_required
def file_delete(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403
    data = request.get_json(silent=True) or {}
    rel = data.get("path", "") or ""
    name = safe_name(data.get("name", ""))
    kind = (data.get("kind") or "file").lower()
    if not name:
        return jsonify({"success": False, "message": "Name required"}), 400
    try:
        target = safe_join_server_path(key, os.path.join(rel, name))
        
        # Check if within server directory
        owner, folder = parse_server_key(key, allow_admin=True)
        server_dir = get_server_dir(owner, folder)
        if not target.startswith(server_dir + os.sep) and target != server_dir:
            return jsonify({"success": False, "message": "Invalid path"}), 400
        
        # Prevent deleting server root
        if target == server_dir:
            return jsonify({"success": False, "message": "Cannot delete server root"}), 400
        
        # Prevent deleting meta.json and server.log
        if os.path.basename(target) in ("meta.json", "server.log"):
            return jsonify({"success": False, "message": "Cannot delete system files"}), 400
        
        if not os.path.exists(target):
            return jsonify({"success": False, "message": "File does not exist"}), 404
        
        if kind == "dir":
            shutil.rmtree(target)
        else:
            os.remove(target)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/files/upload/<path:key>", methods=["POST"])
@login_required
def file_upload(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403

    rel = request.args.get("path", "") or ""
    try:
        base_dir = safe_join_server_path(key, rel)
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 400
    os.makedirs(base_dir, exist_ok=True)

    files = request.files.getlist("files") or []
    if not files:
        one = request.files.get("file")
        if one:
            files = [one]
    if not files:
        return jsonify({"success": False, "message": "No file"}), 400

    relpaths = request.form.getlist("relpaths")
    saved = 0

    for i, f in enumerate(files):
        if not f or not f.filename:
            continue
        filename = os.path.basename(f.filename)

        rp = ""
        if relpaths and i < len(relpaths):
            rp = (relpaths[i] or "").replace("\\", "/").lstrip("/")

        try:
            if rp:
                target_dir = safe_join_server_path(key, os.path.join(rel, os.path.dirname(rp)))
            else:
                target_dir = base_dir
        except Exception:
            continue

        os.makedirs(target_dir, exist_ok=True)
        f.save(os.path.join(target_dir, filename))
        saved += 1

    return jsonify({"success": True, "saved": saved})


# ---------------------------
# Admin APIs (FIXED - Force logout on ban)
# ---------------------------
@app.route("/api/admin/servers")
@admin_required
def admin_servers():
    return jsonify({"success": True, "servers": list_all_servers_for_admin()})


@app.route("/api/admin/server/ban", methods=["POST"])
@admin_required
def admin_server_ban():
    data = request.get_json(silent=True) or {}
    key = (data.get("key") or "").strip()
    banned = bool(data.get("banned", True))

    owner, folder = parse_server_key(key, allow_admin=True)
    server_dir = get_server_dir(owner, folder)
    if not os.path.isdir(server_dir):
        return jsonify({"success": False, "message": "Server not found"}), 404

    meta = read_meta(owner, folder)
    meta["banned"] = banned
    write_meta(owner, folder, meta)

    if banned:
        # Stop the server if running
        stop_proc(key)
        set_state(key, "Banned")
        log_append(key, "[ADMIN] Server banned.\n")
    else:
        set_state(key, "Offline")
        log_append(key, "[ADMIN] Server unbanned.\n")

    return jsonify({"success": True})


@app.route("/api/admin/users")
@admin_required
def admin_users():
    db = load_users()

    counts = {}
    if os.path.isdir(USERS_ROOT):
        for owner in os.listdir(USERS_ROOT):
            root = get_user_servers_root(owner)
            if os.path.isdir(root):
                counts[owner] = len([d for d in os.listdir(root) if os.path.isdir(os.path.join(root, d))])

    users = []
    for u in db.get("users", []):
        users.append({
            "username": u.get("username"),
            "email": u.get("email"),
            "active": bool(u.get("active", True)),
            "premium": bool(u.get("premium", False)),
            "verified": bool(u.get("verified", False)),
            "servers": counts.get(u.get("username") or "", 0),
        })
    return jsonify({"success": True, "users": users})


@app.route("/api/admin/user/update", methods=["POST"])
@admin_required
def admin_user_update():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    if not username:
        return jsonify({"success": False, "message": "Username required"}), 400

    db = load_users()
    u = find_user(db, username)
    if not u:
        return jsonify({"success": False, "message": "User not found"}), 404

    # Track if user was banned
    was_active = u.get("active", True)
    
    if "active" in data:
        u["active"] = bool(data["active"])
    if "premium" in data:
        u["premium"] = bool(data["premium"])

    save_users(db)
    
    # If user was banned (active changed from True to False), force logout
    if "active" in data and not u["active"] and was_active:
        # Clear the session to force immediate logout
        # The session will be checked on next request
        pass

    return jsonify({"success": True})


@app.route("/api/admin/quickstats")
@admin_required
def admin_quickstats():
    total_servers = 0
    running = 0
    installing = 0
    banned = 0

    for s in list_all_servers_for_admin():
        total_servers += 1
        if s.get("status") == "Banned":
            banned += 1
        elif s.get("status") == "Running":
            running += 1
        elif s.get("status") in ("Installing", "Starting"):
            installing += 1

    db = load_users()
    total_users = len(db.get("users", []))
    active_users = sum(1 for u in db.get("users", []) if u.get("active", True))
    premium_users = sum(1 for u in db.get("users", []) if u.get("premium", False))
    verified_users = sum(1 for u in db.get("users", []) if u.get("verified", False))

    return jsonify({"success": True, "stats": {
        "servers_total": total_servers,
        "servers_running": running,
        "servers_installing": installing,
        "servers_banned": banned,
        "users_total": total_users,
        "users_active": active_users,
        "users_premium": premium_users,
        "users_verified": verified_users
    }})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 30170))  # Render uses PORT
    app.run(host="0.0.0.0", port=port)
