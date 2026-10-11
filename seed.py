"""Idempotent database seeding.

Guarantees that on first run:
  * tables exist,
  * the default admin/user accounts exist,
  * every account in historical_transactions.json already has its
    pre-existing transaction history loaded (so users can immediately
    see their average transaction amount).

Safe to call on every app start: it never duplicates data.
"""
import hashlib
import json
import os
from datetime import datetime, timedelta

from data import create_tables, add_user, get_user, get_transactions, add_transaction

HISTORY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "historical_transactions.json")

# username, password, role
DEFAULT_ACCOUNTS = [
    ("admin1", "admin123", "ADMIN"),
    ("admin2", "admin456", "ADMIN"),
    ("user1", "user123", "USER"),
    ("user2", "user456", "USER"),
    ("user3", "user789", "USER"),
]


def hash_password(password):
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def _load_history():
    if not os.path.exists(HISTORY_FILE):
        return {}
    with open(HISTORY_FILE, "r", encoding="utf-8") as fh:
        return json.load(fh)


def ensure_seeded(verbose=False):
    """Create tables, default accounts and pre-existing transactions."""
    create_tables()

    # 1. Accounts
    for username, password, role in DEFAULT_ACCOUNTS:
        if get_user(username) is None:
            add_user(username, hash_password(password), role)
            if verbose:
                print(f"Created account {username} ({role})")

    # 2. Pre-existing transaction history from the data file
    history = _load_history()
    now = datetime.now()

    for username, entries in history.items():
        user = get_user(username)
        if user is None:
            continue
        user_id = user[0]

        # Already seeded (or user has real activity) -> do not touch.
        if get_transactions(user_id):
            continue

        for entry in entries:
            days_ago = int(entry.get("days_ago", 0))
            timestamp = (now - timedelta(days=days_ago)).replace(
                hour=12, minute=0, second=0, microsecond=0
            ).isoformat()
            add_transaction(
                user_id=user_id,
                amount=float(entry["amount"]),
                recipient=str(entry.get("recipient", "Unknown")),
                status="SUCCESS",
                timestamp=timestamp,
            )

        if verbose:
            print(f"Seeded {len(entries)} historical transactions for {username}")

    if verbose:
        print("Database seeded successfully.")


if __name__ == "__main__":
    ensure_seeded(verbose=True)
