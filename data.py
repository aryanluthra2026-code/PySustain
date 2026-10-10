import sqlite3
from datetime import datetime

DB_NAME = "security.db"


def get_connection():
    return sqlite3.connect(DB_NAME)


def create_tables():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('USER', 'ADMIN')),
            created_at TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_logs (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            timestamp TEXT NOT NULL,
            status TEXT NOT NULL,
            ip_address TEXT,
            device TEXT,
            FOREIGN KEY (user_id) REFERENCES users(user_id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            transaction_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            timestamp TEXT NOT NULL,
            recipient TEXT,
            status TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(user_id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS threats (
            threat_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            threat_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            description TEXT,
            status TEXT NOT NULL DEFAULT 'OPEN',
            FOREIGN KEY (user_id) REFERENCES users(user_id)
        )
    """)

    conn.commit()
    conn.close()


# ---------------- USERS ----------------

def add_user(username, password_hash, role="USER"):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO users
        (username, password_hash, role, created_at)
        VALUES (?, ?, ?, ?)
    """, (
        username,
        password_hash,
        role,
        datetime.now().isoformat()
    ))

    conn.commit()
    conn.close()


def get_user(username):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT user_id, username, password_hash, role
        FROM users
        WHERE username = ?
    """, (username,))

    user = cursor.fetchone()

    conn.close()
    return user


# ---------------- LOGIN LOGS ----------------

def record_login(user_id, status, ip_address=None, device=None):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO login_logs
        (user_id, timestamp, status, ip_address, device)
        VALUES (?, ?, ?, ?, ?)
    """, (
        user_id,
        datetime.now().isoformat(),
        status,
        ip_address,
        device
    ))

    conn.commit()
    conn.close()


def get_login_logs():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM login_logs
        ORDER BY timestamp DESC
    """)

    logs = cursor.fetchall()

    conn.close()
    return logs


# ---------------- TRANSACTIONS ----------------

def add_transaction(user_id, amount, recipient, status="SUCCESS"):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO transactions
        (user_id, amount, timestamp, recipient, status)
        VALUES (?, ?, ?, ?, ?)
    """, (
        user_id,
        amount,
        datetime.now().isoformat(),
        recipient,
        status
    ))

    conn.commit()
    conn.close()


def get_transactions(user_id=None):
    conn = get_connection()
    cursor = conn.cursor()

    if user_id:
        cursor.execute("""
            SELECT *
            FROM transactions
            WHERE user_id = ?
            ORDER BY timestamp DESC
        """, (user_id,))
    else:
        cursor.execute("""
            SELECT *
            FROM transactions
            ORDER BY timestamp DESC
        """)

    transactions = cursor.fetchall()

    conn.close()
    return transactions


# ---------------- THREATS ----------------

def add_threat(
    user_id,
    threat_type,
    severity,
    description
):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO threats
        (user_id, threat_type, severity, timestamp, description, status)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        user_id,
        threat_type,
        severity,
        datetime.now().isoformat(),
        description,
        "OPEN"
    ))

    conn.commit()
    conn.close()


def get_threats():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM threats
        ORDER BY timestamp DESC
    """)

    threats = cursor.fetchall()

    conn.close()
    return threats


def update_threat_status(threat_id, status):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE threats
        SET status = ?
        WHERE threat_id = ?
    """, (status, threat_id))

    conn.commit()
    conn.close()
import hashlib


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


# Create the database and tables first
create_tables()


# Pre-existing admin accounts
admins = [
    ("admin1", "admin123"),
    ("admin2", "admin456")
]


# Pre-existing user accounts
users = [
    ("aryan", "aryan123"),
    ("user2", "user456"),
    ("user3", "user789")
]


# Add admins
for username, password in admins:
    try:
        add_user(
            username,
            hash_password(password),
            "ADMIN"
        )
    except Exception:
        print(f"{username} already exists.")


# Add normal users
for username, password in users:
    try:
        add_user(
            username,
            hash_password(password),
            "USER"
        )
    except Exception:
        print(f"{username} already exists.")


print("Initial accounts created successfully.")
# Create database when this file is run
if __name__ == "__main__":
    create_tables()
    print("Database and tables created successfully.")
