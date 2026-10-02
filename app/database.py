import sqlite3
import os
from typing import List, Dict, Any, Optional

DB_FILE = "app_data.db"

def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create tables
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        balance REAL DEFAULT 1000.00
    );
    """)
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        recipient TEXT NOT NULL,
        amount REAL NOT NULL,
        category TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    );
    """)
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT NOT NULL,
        details TEXT NOT NULL,
        ip_address TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    
    # Seed mock admin and user accounts if not exists
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        # Pre-hashed passwords (bcrypt for 'admin123' and 'user123')
        cursor.execute(
            "INSERT INTO users (username, email, password_hash, role, balance) VALUES (?, ?, ?, ?, ?)",
            ("admin", "admin@devsecops-bank.internal", "$2b$12$e8YxG6v/XwP3hRjJ5z.0au7b9b0A1b2C3d4E5f6G7h8I9j0K1l2m.", "admin", 99999.0)
        )
        cursor.execute(
            "INSERT INTO users (username, email, password_hash, role, balance) VALUES (?, ?, ?, ?, ?)",
            ("alice", "alice@example.com", "$2b$12$e8YxG6v/XwP3hRjJ5z.0au7b9b0A1b2C3d4E5f6G7h8I9j0K1l2m.", "user", 2450.50)
        )
        cursor.execute(
            "INSERT INTO users (username, email, password_hash, role, balance) VALUES (?, ?, ?, ?, ?)",
            ("bob", "bob@example.com", "$2b$12$e8YxG6v/XwP3hRjJ5z.0au7b9b0A1b2C3d4E5f6G7h8I9j0K1l2m.", "user", 820.00)
        )
        
        # Seed transactions
        cursor.execute(
            "INSERT INTO transactions (user_id, recipient, amount, category) VALUES (?, ?, ?, ?)",
            (2, "Cloud Hosting AWS", 120.00, "Infrastructure")
        )
        cursor.execute(
            "INSERT INTO transactions (user_id, recipient, amount, category) VALUES (?, ?, ?, ?)",
            (2, "GitHub Team Sub", 45.00, "DevTools")
        )
        cursor.execute(
            "INSERT INTO transactions (user_id, recipient, amount, category) VALUES (?, ?, ?, ?)",
            (3, "Coffee Shop", 8.50, "Food & Beverage")
        )
        
    conn.commit()
    conn.close()

# Safe query function
def find_user_by_username_safe(username: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

# Vulnerable query function for SAST/DAST educational verification
def search_users_vulnerable(query_str: str) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    # INTENTIONAL DEMO VULNERABILITY (CWE-89 SQL Injection) for SAST / Semgrep detection
    raw_sql = f"SELECT id, username, email, role FROM users WHERE username LIKE '%{query_str}%' OR email LIKE '%{query_str}%'"
    cursor.execute(raw_sql)
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

# Secure search function for comparison & remediation
def search_users_secure(query_str: str) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    param = f"%{query_str}%"
    cursor.execute("SELECT id, username, email, role FROM users WHERE username LIKE ? OR email LIKE ?", (param, param))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]
