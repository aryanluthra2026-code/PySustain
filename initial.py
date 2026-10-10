from data import create_tables, add_user
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
    ("user1", "user123"),
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
