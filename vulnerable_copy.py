# vulnerable_app.py
# WARNING: This code is intentionally vulnerable for educational purposes only!

import sqlite3
import hashlib
import os

# Hardcoded credentials - VULNERABILITY 1
SECRET_KEY = "admin123"
DB_PASSWORD = "password123"

def get_db_connection():
    # No connection pooling, plain text credentials - VULNERABILITY 2
    conn = sqlite3.connect("users.db")
    return conn

def create_table():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users 
                      (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)''')
    conn.commit()
    conn.close()

def login(username, password):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # SQL INJECTION VULNERABILITY - VULNERABILITY 3
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return True, "Login successful! Welcome " + username
    return False, "Invalid credentials"

def register_user(username, password, role="user"):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Storing plain text password - VULNERABILITY 4
    # No input validation - VULNERABILITY 5
    cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                   (username, password, role))
    conn.commit()
    conn.close()
    return "User registered successfully"

def get_user_data(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # No authorization check - VULNERABILITY 6
    query = "SELECT * FROM users WHERE id = " + str(user_id)
    cursor.execute(query)
    data = cursor.fetchone()
    conn.close()
    return data

def save_file(filename, content):
    # Path traversal vulnerability - VULNERABILITY 7
    with open(filename, 'w') as f:
        f.write(content)
    return "File saved: " + filename

def execute_command(user_input):
    # Command injection vulnerability - VULNERABILITY 8
    os.system("echo " + user_input)

def weak_hash(password):
    # Using MD5 for password hashing - VULNERABILITY 9
    return hashlib.md5(password.encode()).hexdigest()

# Debug mode enabled in production - VULNERABILITY 10
DEBUG = True

if __name__ == "__main__":
    create_table()
    register_user("admin", "admin123", "admin")
    register_user("user1", "pass123", "user")
    
    # Test login
    success, msg = login("admin", "admin123")
    print(msg)
    
    # SQL Injection test (shows vulnerability)
    success, msg = login("' OR '1'='1", "anything")
    print(msg)
