import hashlib

import streamlit as st

from data import get_user
from detection import (
    MAX_FAILED_ATTEMPTS,
    LOCKOUT_MINUTES,
    check_login_allowed,
    get_ip_block_state,
    get_lockout_state,
    register_failed_login,
    register_successful_login,
)


def hash_password(password):
    """Match the SHA-256 hashing used by the existing database."""
    return hashlib.sha256(
        password.encode("utf-8")
    ).hexdigest()


def client_ip():
    """Best-effort client IP (proxy header when available)."""
    try:
        headers = st.context.headers
        forwarded = headers.get("x-forwarded-for") or headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        real = headers.get("x-real-ip") or headers.get("X-Real-IP")
        if real:
            return real.strip()
    except Exception:
        pass
    return "127.0.0.1"


def authenticate(username, password):
    """
    Verify credentials against the existing users table.

    Returns:
        (True, user, message) on success
        (False, None, message) on failure
    """
    username = username.strip()
    user = get_user(username)

    if user is None:
        # Don't reveal whether a username exists.
        return False, None, "Invalid username or password."

    if hash_password(password) != str(user[2]):
        return False, None, "Invalid username or password."

    return True, user, "Login successful."


FEATURES = [
    ("Brute-force shield",
     "5 failed logins lock the account; 8 from one network block the IP — "
     "automatically."),
    ("Baseline payment scoring",
     "Z-scored against your regular average; unusual amounts are held or "
     "declined."),
    ("Instant response",
     "Lockouts, network blocks and threat records fire with no human in the "
     "loop."),
]

SECURITY_FACTS = [
    ("Failures / lock", "5"),
    ("Auto lockout", "15 min"),
    ("Fraud gate", "3-sigma"),
    ("Monitoring", "24/7"),
]


def show_login_page():
    """Pure-Python login page; every attempt runs the automatic
    brute-force guard before/after credential verification."""

    ip = client_ip()

    banner = st.container()  # holds multiple stacked feedback messages

    st.title("FADE Pay — Secure Payment Gateway")
    st.caption("TLS ENCRYPTED · 3-D SECURE · FRAUD ANALYSIS & DETECTION ENGINE")

    left, right = st.columns([1.1, 0.9], gap="large")

    with left:
        st.header("Payments, guarded by intelligence.")
        st.write(
            "Every login is watched for brute-force attacks. Every payment is "
            "scored against your own spending baseline — before it moves."
        )
        for title, detail in FEATURES:
            st.subheader(title)
            st.caption(detail)

        stat_cols = st.columns(len(SECURITY_FACTS))
        for col, (label, value) in zip(stat_cols, SECURITY_FACTS):
            col.metric(label, value)

    with right:
        with st.form("fade_login_form"):
            st.subheader("Sign in")
            st.caption("Access your gateway dashboard.")

            username = st.text_input("Username", placeholder="e.g. user1",
                                     icon=":material/person:")
            password = st.text_input("Password", type="password",
                                     placeholder="........", icon=":material/key:")
            submitted = st.form_submit_button(
                "Log In", type="primary", width="stretch",
                icon=":material/arrow_forward:",
            )

            st.caption("Demo accounts")
            st.code("user1 / user123  ·  user2 / user456  ·  user3 / user789",
                    language=None)
            st.code("admin1 / admin123 — security operations", language=None)

    if not submitted:
        if username.strip():
            state = get_lockout_state(get_user(username.strip()))
            if state["locked"]:
                minutes = max(1, state["remaining_seconds"] // 60 + 1)
                banner.warning(
                    f"This account is locked for ~{minutes} more minute(s) "
                    f"after {MAX_FAILED_ATTEMPTS} failed attempts."
                )
        return

    if not username.strip() or not password:
        banner.warning("Enter both your username and password.")
        return

    try:
        # ---- AUTOMATIC BRUTE-FORCE GATE (runs before the password check)
        allowed, gate_message = check_login_allowed(username, ip)
        if not allowed:
            banner.error(gate_message)
            banner.info("This block was applied automatically by the attack detector.")
            return

        success, user, message = authenticate(username, password)

        if success:
            register_successful_login(user, ip)
            st.session_state["authenticated"] = True
            st.session_state["user_id"] = user[0]
            st.session_state["username"] = user[1]
            st.session_state["role"] = user[3]
            st.session_state["login_ip"] = ip
            st.session_state["flash"] = (
                "success",
                "Login successful. Welcome to your payment gateway.",
            )
            st.rerun()

        # ---- FAILED ATTEMPT: record, count, and act automatically ----
        existing_user = get_user(username.strip())
        actions = register_failed_login(existing_user, ip)

        banner.error("Invalid username or password.")

        if actions["locked_account"]:
            banner.error(
                f"Account locked for {LOCKOUT_MINUTES} minutes after "
                f"{MAX_FAILED_ATTEMPTS} failed attempts. "
                f"A CRITICAL threat was raised automatically."
            )
        elif existing_user is not None:
            remaining = max(
                0,
                MAX_FAILED_ATTEMPTS - int(existing_user[4] or 0) - 1,
            )
            if remaining <= 1:
                banner.warning(
                    f"{remaining} attempt(s) remaining before this "
                    f"account is automatically locked."
                )
            else:
                banner.info(f"{remaining} attempt(s) remaining before lockout.")

        if actions["threats_created"] > 0:
            banner.warning(
                "Security operations have been notified — a threat "
                "record was created automatically."
            )

        ip_state = get_ip_block_state(ip)
        if ip_state["blocked"]:
            banner.error(
                f"This network has been blocked after "
                f"{ip_state['failures']} recent failed attempts."
            )

    except Exception as error:
        banner.error(f"Login could not be completed: {error}")


def logout():
    """Clear the current login session."""
    for key in (
        "authenticated",
        "user_id",
        "username",
        "role",
        "login_ip",
        "flash",
        "receipt",
        "monitor_verdict",
    ):
        st.session_state.pop(key, None)

    st.rerun()
