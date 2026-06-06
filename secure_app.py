# secure_app.py
# FIXED VERSION - Secure coding best practices applied

import sqlite3
import hashlib
import hmac
import os
import re
import secrets
import logging

# Logging setup (no sensitive data in logs)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# FIX 1: No hardcoded credentials — use environment variables
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))
DB_PATH = os.environ.get("DB_PATH", "secure_users.db")

# FIX 10: Debug mode from environment only
DEBUG = os.environ.get("DEBUG", "False").lower() == "true"

def get_db_connection():
    # FIX 2: Safe DB connection
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def create_table():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                      id INTEGER PRIMARY KEY AUTOINCREMENT,
                      username TEXT UNIQUE NOT NULL,
                      password_hash TEXT NOT NULL,
                      salt TEXT NOT NULL,
                      role TEXT DEFAULT 'user',
                      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    conn.commit()
    conn.close()

def hash_password(password: str, salt: str = None) -> tuple:
    """FIX 9: Use SHA-256 with salt instead of MD5"""
    if salt is None:
        salt = secrets.token_hex(32)
    password_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        iterations=100000
    )
    return password_hash.hex(), salt

def validate_input(username: str, password: str) -> tuple:
    """FIX 5: Input validation"""
    # Username: 3-20 chars, alphanumeric + underscore only
    if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
        return False, "Username must be 3-20 characters (letters, numbers, underscore only)"
    # Password: minimum 8 chars
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    return True, "Valid"

def login(username: str, password: str, current_user_id: int = None) -> tuple:
    """FIX 3: Parameterized queries — no SQL injection possible"""
    # Input validation
    is_valid, msg = validate_input(username, password)
    if not is_valid:
        return False, msg

    conn = get_db_connection()
    cursor = conn.cursor()

    # FIX 3: Parameterized query
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()

    if user:
        # Verify password securely
        stored_hash = user['password_hash']
        salt = user['salt']
        input_hash, _ = hash_password(password, salt)

        # FIX: Use hmac.compare_digest to prevent timing attacks
        if hmac.compare_digest(input_hash, stored_hash):
            logger.info(f"Successful login for user: {username}")
            return True, f"Login successful! Welcome {username}"

    logger.warning(f"Failed login attempt for username: {username}")
    return False, "Invalid credentials"

def register_user(username: str, password: str, role: str = "user") -> tuple:
    """FIX 4 & 5: Hashed passwords + input validation"""
    is_valid, msg = validate_input(username, password)
    if not is_valid:
        return False, msg

    # Only allow valid roles
    if role not in ["user", "admin"]:
        return False, "Invalid role"

    # FIX 4: Hash password before storing
    password_hash, salt = hash_password(password)

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash, salt, role) VALUES (?, ?, ?, ?)",
            (username, password_hash, salt, role)
        )
        conn.commit()
        logger.info(f"New user registered: {username}")
        return True, "User registered successfully"
    except sqlite3.IntegrityError:
        return False, "Username already exists"
    finally:
        conn.close()

def get_user_data(user_id: int, requesting_user_id: int, requesting_user_role: str) -> tuple:
    """FIX 6: Authorization check before data access"""
    # Only admin or the user themselves can access the data
    if requesting_user_role != "admin" and requesting_user_id != user_id:
        logger.warning(f"Unauthorized data access attempt by user {requesting_user_id}")
        return None, "Unauthorized: Access denied"

    conn = get_db_connection()
    cursor = conn.cursor()
    # FIX 3: Parameterized query
    cursor.execute("SELECT id, username, role, created_at FROM users WHERE id = ?", (user_id,))
    data = cursor.fetchone()
    conn.close()

    if data:
        return dict(data), "Success"
    return None, "User not found"

def save_file(filename: str, content: str, allowed_dir: str = "./uploads/") -> tuple:
    """FIX 7: Path traversal prevention"""
    # Sanitize filename — only allow alphanumeric, dash, underscore, dot
    safe_filename = re.sub(r'[^a-zA-Z0-9_\-\.]', '', os.path.basename(filename))
    if not safe_filename:
        return False, "Invalid filename"

    # Ensure file stays within allowed directory
    safe_path = os.path.realpath(os.path.join(allowed_dir, safe_filename))
    allowed_path = os.path.realpath(allowed_dir)

    if not safe_path.startswith(allowed_path):
        logger.warning(f"Path traversal attempt blocked: {filename}")
        return False, "Invalid file path"

    os.makedirs(allowed_dir, exist_ok=True)
    with open(safe_path, 'w') as f:
        f.write(content)
    return True, f"File saved safely: {safe_filename}"

def execute_command(user_input: str) -> tuple:
    """FIX 8: No OS command injection — use subprocess with args list"""
    import subprocess
    # Whitelist allowed commands only
    allowed_commands = ["ls", "pwd", "whoami"]
    command = user_input.strip().split()[0] if user_input.strip() else ""

    if command not in allowed_commands:
        return False, f"Command not allowed. Allowed: {allowed_commands}"

    result = subprocess.run([command], capture_output=True, text=True, timeout=5)
    return True, result.stdout

if __name__ == "__main__":
    create_table()
    success, msg = register_user("admin", "SecurePass@123", "admin")
    print(msg)
    success, msg = register_user("user1", "MyPass@456", "user")
    print(msg)

    # Test login
    success, msg = login("admin", "SecurePass@123")
    print(msg)

    # SQL Injection attempt — blocked!
    success, msg = login("' OR '1'='1", "anything")
    print(msg)
