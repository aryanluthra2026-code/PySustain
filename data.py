import os
import sqlite3
from datetime import datetime

# Overridable so tests can run against an isolated database file.
DB_NAME = os.environ.get("FADE_DB", "security.db")


def get_connection():
    return sqlite3.connect(DB_NAME)


def _ensure_column(cursor, table, column, declaration):
    """Add a column to an existing table if it is missing (migration)."""
    cursor.execute(f"PRAGMA table_info({table})")
    existing = {row[1] for row in cursor.fetchall()}
    if column not in existing:
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {declaration}")


def create_tables():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('USER', 'ADMIN')),
            created_at TEXT NOT NULL,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until TEXT
        )
    """)

    # Migrate databases created before brute-force lockout support existed.
    _ensure_column(cursor, "users", "failed_attempts", "INTEGER NOT NULL DEFAULT 0")
    _ensure_column(cursor, "users", "locked_until", "TEXT")

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
    """Return user record including brute-force security state.

    Indexes: 0 user_id, 1 username, 2 password_hash, 3 role,
             4 failed_attempts, 5 locked_until
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT user_id, username, password_hash, role,
               failed_attempts, locked_until
        FROM users
        WHERE username = ?
    """, (username,))

    user = cursor.fetchone()

    conn.close()
    return user


def get_all_users():
    """All accounts: (user_id, username, role, locked_until)."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT user_id, username, role, locked_until
        FROM users
        ORDER BY user_id
    """)
    rows = cursor.fetchall()
    conn.close()
    return rows


def set_failed_attempts(user_id, count):
    conn = get_connection()
    conn.execute(
        "UPDATE users SET failed_attempts = ? WHERE user_id = ?",
        (int(count), user_id),
    )
    conn.commit()
    conn.close()


def set_lockout(user_id, locked_until):
    """Lock (ISO timestamp) or clear (None) the account lockout."""
    conn = get_connection()
    conn.execute(
        "UPDATE users SET locked_until = ? WHERE user_id = ?",
        (locked_until, user_id),
    )
    conn.commit()
    conn.close()


def unlock_account(user_id):
    """Automatic recovery action: reset counters and lift the lockout."""
    conn = get_connection()
    conn.execute(
        "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE user_id = ?",
        (user_id,),
    )
    conn.commit()
    conn.close()


def get_locked_accounts():
    """All accounts currently locked out, with lock expiry."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT user_id, username, role, failed_attempts, locked_until
        FROM users
        WHERE locked_until IS NOT NULL
        ORDER BY locked_until DESC
    """)
    rows = cursor.fetchall()

    conn.close()
    return rows


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


def count_failed_logins(ip_address=None, user_id=None, since=None):
    """Count FAILED login events matching the given filters."""
    conn = get_connection()
    cursor = conn.cursor()

    query = "SELECT COUNT(*) FROM login_logs WHERE status = 'FAILED'"
    params = []

    if ip_address is not None:
        query += " AND ip_address = ?"
        params.append(ip_address)
    if user_id is not None:
        query += " AND user_id = ?"
        params.append(user_id)
    if since is not None:
        query += " AND timestamp >= ?"
        params.append(since)

    cursor.execute(query, params)
    count = cursor.fetchone()[0]

    conn.close()
    return count


def last_failed_login_time(ip_address=None):
    """Most recent FAILED login timestamp for an IP (or None)."""
    conn = get_connection()
    cursor = conn.cursor()

    query = "SELECT MAX(timestamp) FROM login_logs WHERE status = 'FAILED'"
    params = []
    if ip_address is not None:
        query += " AND ip_address = ?"
        params.append(ip_address)

    cursor.execute(query, params)
    row = cursor.fetchone()

    conn.close()
    return row[0] if row else None


# ---------------- TRANSACTIONS ----------------
def add_transaction(user_id, amount, recipient, status="SUCCESS", timestamp=None):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO transactions
        (user_id, amount, timestamp, recipient, status)
        VALUES (?, ?, ?, ?, ?)
    """, (
        user_id,
        amount,
        timestamp or datetime.now().isoformat(),
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
