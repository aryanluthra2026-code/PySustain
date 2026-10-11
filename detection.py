"""Automatic brute-force / credential-stuffing detection.

Every login attempt (from the UI or from the admin simulator) runs
through this module.  When thresholds are breached the module takes the
action itself — it does not wait for a human to press a button:

  * per-account lockout      after MAX_FAILED_ATTEMPTS failures
  * per-network (IP) block   after IP_FAILURE_THRESHOLD failures in a window
  * threat records           created automatically (with de-duplication)
  * login evidence           written to login_logs for the audit trail

`detect_repeated_failed_logins` remains available as a full-history
re-scan from the admin Threat Center.
"""
from datetime import datetime, timedelta

from data import (
    add_threat,
    count_failed_logins,
    get_login_logs,
    get_threats,
    get_user,
    record_login,
    set_failed_attempts,
    set_lockout,
    last_failed_login_time,
)

# ---- Thresholds (tune here) --------------------------------------------
MAX_FAILED_ATTEMPTS = 5          # failures per account before lockout
LOCKOUT_MINUTES = 15             # account lockout duration
IP_FAILURE_THRESHOLD = 8         # failures from one IP inside the window
IP_WINDOW_MINUTES = 5            # sliding window for counting IP failures
IP_BLOCK_MINUTES = 10            # IP block duration after the last failure

DEVICE_LABEL = "FADE Web App"


# ---- Helpers ------------------------------------------------------------
def _now():
    return datetime.now()


def _iso(dt):
    return dt.isoformat()


def parse_ts(value):
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None


def _has_open_threat(user_id, threat_type):
    for threat in get_threats():
        if (threat[1] == user_id
                and threat[2] == threat_type
                and str(threat[6]).upper() == "OPEN"):
            return True
    return False


def _create_threat(user_id, threat_type, severity, description, dedupe=True):
    """Create a threat unless an identical open one already exists."""
    if dedupe and _has_open_threat(user_id, threat_type):
        return False
    add_threat(user_id, threat_type, severity, description)
    return True


# ---- Account lockout state ---------------------------------------------
def get_lockout_state(user):
    """Return lockout info for a user row (from data.get_user).

    Returns dict: locked (bool), remaining_seconds, failed_attempts.
    """
    if user is None:
        return {"locked": False, "remaining_seconds": 0, "failed_attempts": 0}

    failed_attempts = int(user[4] or 0)
    locked_until = user[5]

    if not locked_until:
        return {"locked": False, "remaining_seconds": 0,
                "failed_attempts": failed_attempts}

    until = parse_ts(locked_until)
    if until is None or until <= _now():
        # Lock expired -> clear it (automatic recovery).
        set_lockout(user[0], None)
        set_failed_attempts(user[0], 0)
        return {"locked": False, "remaining_seconds": 0, "failed_attempts": 0}

    remaining = int((until - _now()).total_seconds())
    return {"locked": True, "remaining_seconds": remaining,
            "failed_attempts": failed_attempts}


def get_ip_block_state(ip_address):
    """Rolling IP block: active while >= threshold failures happened in the
    window, lasting IP_BLOCK_MINUTES after the most recent failure."""
    since = _iso(_now() - timedelta(minutes=IP_WINDOW_MINUTES))
    failures = count_failed_logins(ip_address=ip_address, since=since)

    if failures < IP_FAILURE_THRESHOLD:
        return {"blocked": False, "failures": failures,
                "remaining_seconds": 0}

    last_fail = parse_ts(last_failed_login_time(ip_address=ip_address))
    if last_fail is None:
        return {"blocked": False, "failures": failures,
                "remaining_seconds": 0}

    until = last_fail + timedelta(minutes=IP_BLOCK_MINUTES)
    if until <= _now():
        return {"blocked": False, "failures": failures,
                "remaining_seconds": 0}

    remaining = int((until - _now()).total_seconds())
    return {"blocked": True, "failures": failures,
            "remaining_seconds": remaining}


def check_login_allowed(username, ip_address):
    """Pre-authentication gate.  Returns (allowed, message).

    Checks the network block first, then the account lockout.  Both are
    enforced BEFORE the password is verified.
    """
    ip_state = get_ip_block_state(ip_address)
    if ip_state["blocked"]:
        minutes = max(1, ip_state["remaining_seconds"] // 60 + 1)
        return False, (
            f"Too many failed attempts from this network "
            f"({ip_state['failures']} in {IP_WINDOW_MINUTES} min). "
            f"Access blocked for ~{minutes} minute(s)."
        )

    user = get_user(username.strip()) if username and username.strip() else None
    if user is None:
        return True, ""

    lock = get_lockout_state(user)
    if lock["locked"]:
        minutes = max(1, lock["remaining_seconds"] // 60 + 1)
        return False, (
            f"Account temporarily locked after {MAX_FAILED_ATTEMPTS} "
            f"failed login attempts. Try again in ~{minutes} minute(s)."
        )

    return True, ""


# ---- Registering outcomes (the automatic actions) -----------------------
def register_failed_login(user, ip_address, device=DEVICE_LABEL):
    """Record a failed attempt, increment counters, and take automatic
    action (lock account / block IP / raise threat) when thresholds hit.

    Returns dict describing the actions taken.
    """
    actions = {"locked_account": False, "blocked_ip": False,
               "threats_created": 0}
    user_id = user[0] if user is not None else None

    record_login(user_id, "FAILED", ip_address, device)

    # --- Per-account brute force -------------------------------------
    if user is not None:
        attempts = int(user[4] or 0) + 1
        set_failed_attempts(user_id, attempts)

        if attempts >= MAX_FAILED_ATTEMPTS:
            lock_until = _iso(_now() + timedelta(minutes=LOCKOUT_MINUTES))
            set_lockout(user_id, lock_until)
            actions["locked_account"] = True

            if _create_threat(
                user_id,
                "BRUTE FORCE ATTACK",
                "CRITICAL",
                (
                    f"Account '{user[1]}' locked: {attempts} failed login "
                    f"attempts (threshold {MAX_FAILED_ATTEMPTS}). "
                    f"Locked until {lock_until} from IP {ip_address}."
                ),
            ):
                actions["threats_created"] += 1
        elif attempts == MAX_FAILED_ATTEMPTS - 1:
            # Warning-level threat one attempt before the lockout.
            if _create_threat(
                user_id,
                "Multiple Failed Logins",
                "HIGH",
                (
                    f"{attempts} failed login attempts for user "
                    f"'{user[1]}' — account will lock at "
                    f"{MAX_FAILED_ATTEMPTS} (IP {ip_address})."
                ),
            ):
                actions["threats_created"] += 1

    # --- Network-level burst (credential stuffing / distributed attack)
    ip_state = get_ip_block_state(ip_address)
    if ip_state["blocked"]:
        if _create_threat(
            None,
            "NETWORK BRUTE FORCE ATTACK",
            "HIGH",
            (
                f"{ip_state['failures']} failed logins from IP "
                f"{ip_address} within {IP_WINDOW_MINUTES} minutes. "
                f"Network access blocked for {IP_BLOCK_MINUTES} minutes."
            ),
        ):
            actions["threats_created"] += 1

    return actions


def register_successful_login(user, ip_address, device=DEVICE_LABEL):
    """Successful login -> reset counters (automatic recovery) and log it."""
    user_id = user[0]
    set_failed_attempts(user_id, 0)
    set_lockout(user_id, None)
    record_login(user_id, "SUCCESS", ip_address, device)


# ---- Full-history re-scan (admin button) --------------------------------
def detect_repeated_failed_logins(threshold=3):
    """Re-scan ALL recorded failures and create missing alerts."""
    logs = get_login_logs()

    failed_counts = {}
    for log in logs:
        user_id = log[1]
        status = str(log[3]).upper()
        if user_id is not None and status == "FAILED":
            failed_counts[user_id] = failed_counts.get(user_id, 0) + 1

    alerts_created = 0
    for user_id, count in failed_counts.items():
        if count >= threshold and _create_threat(
            user_id,
            "Multiple Failed Logins",
            "HIGH",
            f"{count} failed login events recorded for user {user_id}.",
        ):
            alerts_created += 1

    return alerts_created
