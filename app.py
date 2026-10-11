from datetime import datetime, timedelta

import pandas as pd
import streamlit as st

from seed import ensure_seeded

# Idempotent startup: tables + default accounts + pre-existing
# transaction history from historical_transactions.json.
ensure_seeded()

from data import (
    add_threat,
    count_failed_logins,
    get_all_users,
    get_locked_accounts,
    get_login_logs,
    get_threats,
    get_transactions,
    get_user,
    unlock_account,
    update_threat_status,
)
from detection import (
    MAX_FAILED_ATTEMPTS,
    LOCKOUT_MINUTES,
    IP_FAILURE_THRESHOLD,
    IP_WINDOW_MINUTES,
    IP_BLOCK_MINUTES,
    detect_repeated_failed_logins,
    get_lockout_state,
    register_failed_login,
    register_successful_login,
)
from fraud_detector import FraudDetector, ALLOW, REVIEW, BLOCK
from auth import show_login_page, logout


# ==================================================
# PAGE CONFIGURATION  (all theming lives in .streamlit/config.toml)
# ==================================================

st.set_page_config(
    page_title="FADE  | Secure Payment Gateway",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ==================================================
# AUTHENTICATION GATE
# ==================================================

if not st.session_state.get("authenticated", False):
    show_login_page()
    st.stop()


# Render any queued confirmation banner (set before st.rerun()).
_pending_flash = st.session_state.pop("flash", None)
if _pending_flash:
    _kind, _msg = _pending_flash
    getattr(st, _kind)(_msg)

username = st.session_state.get("username", "User")
role = str(st.session_state.get("role", "USER")).upper()
user_id = st.session_state["user_id"]
detector = FraudDetector()


# ==================================================
# SIDEBAR (pure Python)
# ==================================================

st.sidebar.title("FADE")
st.sidebar.caption("Secure Payment Gateway")
st.sidebar.divider()

st.sidebar.write(f"Signed in as **{username}**")
st.sidebar.caption(f"Role: {role} · IP: {st.session_state.get('login_ip', '127.0.0.1')}")

if st.sidebar.button("Log Out", icon=":material/logout:", width="stretch"):
    logout()

st.sidebar.divider()
st.sidebar.caption("NAVIGATION")

if role == "ADMIN":
    available_pages = [
        "Overview",
        "Threat Center",
        "Authentication Logs",
        "Fraud Activity",
    ]
else:
    available_pages = [
        "Dashboard",
        "Make a Payment",
        "My Transactions",
        "Security Alerts",
    ]

page = st.sidebar.radio("Navigation", available_pages, label_visibility="collapsed")

st.sidebar.divider()
st.sidebar.caption("PROTECTION")

me = get_user(username)
lock = get_lockout_state(me)
if lock["locked"]:
    st.sidebar.error("Account Locked")
else:
    st.sidebar.success("Login Shield: Active")
    st.sidebar.success("Fraud Shield: Active")
    if role != "ADMIN":
        st.sidebar.caption(
            f"{lock['failed_attempts']}/{MAX_FAILED_ATTEMPTS} failed attempts "
            f"used · auto-lock at {MAX_FAILED_ATTEMPTS}"
        )

st.sidebar.caption("FADE · Fraud Analysis & Detection Engine")


# ==================================================
# PYTHON UI HELPERS
# ==================================================

LOGIN_COLUMNS = ["Log ID", "User ID", "Timestamp", "Status", "IP Address", "Device"]
THREAT_COLUMNS = ["Threat ID", "User ID", "Threat Type", "Severity",
                  "Created At", "Description", "Status"]
TRANSACTION_COLUMNS = ["Transaction ID", "User ID", "Amount", "Timestamp",
                       "Recipient", "Status"]

STATUS_LABEL = {
    "SUCCESS": "APPROVED",
    "FLAGGED": "HELD FOR REVIEW",
    "BLOCKED": "DECLINED",
    "FAILED": "FAILED",
    "OPEN": "OPEN",
    "INVESTIGATING": "INVESTIGATING",
    "RESOLVED": "RESOLVED",
}


def flash(kind, message):
    """Queue a one-shot confirmation banner that survives st.rerun()."""
    st.session_state["flash"] = (kind, message)


def money(value):
    try:
        return f"₹{float(value):,.2f}"
    except (TypeError, ValueError):
        return str(value)


def badge(value):
    return STATUS_LABEL.get(str(value).upper(), value)


def page_head(title, sub=None, note=None):
    st.title(title)
    if sub:
        st.caption(sub)
    if note:
        st.caption(note)


def section(title, sub=None):
    st.subheader(title)
    if sub:
        st.caption(sub)


def tiles(items):
    """items: list of (label, value, sub) tuples -> native metric tiles."""
    cols = st.columns(len(items))
    for col, item in zip(cols, items):
        label, value = item[0], item[1]
        sub = item[2] if len(item) > 2 else ""
        col.metric(label, value)
        if sub:
            col.caption(sub)


def card_vis(name, avg_text):
    """Card details rendered with native code/caption blocks."""
    st.code("•••• •••• •••• 4271     FADE SIGNATURE", language=None)
    st.write(f"**Cardholder:** {name}")
    st.write(f"**Regular spend:** {avg_text}")


def gauge_panel(amount, base):
    """Native progress gauge: where this amount sits vs the baseline."""
    mean, std, count = base["mean"], base["std"], base["count"]
    if count == 0 or mean <= 0:
        st.info("No baseline yet — make your first payment.")
        return

    hi = max(mean + 3.5 * std, float(amount) * 1.08, mean * 1.2)
    frac = max(0.0, min(1.0, float(amount) / hi)) if hi else 0.0
    st.progress(frac, text=f"{money(amount)} of scale {money(hi)}")

    low = max(0.0, mean - 2 * std)
    st.caption(f"Safe zone: {money(low)} – {money(mean + 2 * std)} · average {money(mean)}")

    verdict = detector.evaluate(st.session_state["user_id"], float(amount))
    label = {ALLOW: "Approve", REVIEW: "Hold", BLOCK: "Decline"}[verdict.decision]
    st.write(f"Projected outcome: **{label}**")


def verdict_box(decision, title, detail):
    message = f"{title} — {detail}"
    if decision == ALLOW:
        st.success(message)
    elif decision == REVIEW:
        st.warning(message)
    else:
        st.error(message)


def receipt_table(rc):
    d = rc["decision"]
    rows = [
        ("Recipient", rc["recipient"]),
        ("Your average", money(d.mean)),
        ("Deviation", f"{d.deviation_pct:+.1f}% ({d.z_score:+.2f}σ)"),
        ("Baseline samples", f"{d.history_count} payments"),
        ("Status", rc["status"]),
        ("Reference", rc["reference"]),
        ("When", rc["when"]),
    ]
    st.table(pd.DataFrame(rows, columns=["Field", "Value"]))


def display_table(data, columns, empty_message):
    if not data:
        st.info(empty_message)
        return
    try:
        df = pd.DataFrame(data, columns=columns)
        if "Status" in df.columns:
            df["Status"] = df["Status"].map(badge)
        st.dataframe(df, width="stretch", hide_index=True)
    except Exception as error:
        st.error(f"Could not display records: {error}")


# ==================================================
# LOAD DATA
# ==================================================

try:
    threats = get_threats()
    login_logs = get_login_logs()
    all_transactions = get_transactions()
except Exception as error:
    st.error(f"Could not load data: {error}")
    st.stop()


# ==================================================
# 1. USER: DASHBOARD
# ==================================================

if page == "Dashboard":
    page_head("Payment Dashboard",
              f"Welcome back, {username} — your money, watched by AI.",
              "Live monitoring active")

    my_tx = [tx for tx in all_transactions if tx[1] == user_id]
    approved = [tx for tx in my_tx if tx[5] == "SUCCESS"]
    base = detector.baseline(user_id)
    held = sum(1 for tx in my_tx if tx[5] in ("FLAGGED", "BLOCKED"))

    tiles([
        ("Average Payment", money(base["mean"]),
         f"from {base['count']} past payments"),
        ("Approved Payments", str(len(approved)), "settled & cleared"),
        ("Last Payment", money(my_tx[0][2]) if my_tx else "—",
         my_tx[0][4] if my_tx else "no activity yet"),
        ("Held / Declined", str(held), "fraud-shield interventions"),
    ])

    left, right = st.columns([1.25, 1], gap="large")

    with left:
        section("Your Card", "linked to your spending profile")
        card_vis(username.upper(), money(base["mean"]))
        st.info(
            f"Typical range {money(base['mean'] - 2 * base['std'])} – "
            f"{money(base['mean'] + 2 * base['std'])} · 2-sigma envelope "
            f"around your average {money(base['mean'])}"
        )

        section("Spending Timeline", "approved payments over time")
        if len(approved) >= 2:
            series = (
                pd.DataFrame(approved, columns=TRANSACTION_COLUMNS)
                .sort_values("Timestamp")
                .set_index("Timestamp")["Amount"]
            )
            st.line_chart(series, height=320)
        else:
            st.info("Make a payment to start building your profile.")

    with right:
        section("Protection", "always on, never asked")
        st.caption(
            f"Brute-force shield: auto-lock after {MAX_FAILED_ATTEMPTS} "
            f"failed logins ({LOCKOUT_MINUTES} min)"
        )
        st.caption(
            f"Network block after {IP_FAILURE_THRESHOLD} failures / "
            f"{IP_WINDOW_MINUTES} min ({IP_BLOCK_MINUTES} min block)"
        )
        st.caption(
            f"Failed attempts used this session: "
            f"{lock['failed_attempts']}/{MAX_FAILED_ATTEMPTS}"
        )
        st.caption(
            "Payment fraud shield: declines at 3.0-sigma or 3x your average; "
            "holds at 2.0-sigma or 1.75x"
        )

        my_threats = [t for t in threats if t[1] == user_id]
        if my_threats:
            st.warning(
                f"{len(my_threats)} security alert(s) on your account — "
                f"see the Security Alerts page."
            )
        else:
            st.success("No security alerts on your account.")

    section("Recent Activity", "flagged events surface first")
    flagged_recent = [tx for tx in my_tx if tx[5] != "SUCCESS"]
    display_table(
        flagged_recent[:6] if flagged_recent else my_tx[:6],
        TRANSACTION_COLUMNS,
        "No recent activity.",
    )


# ==================================================
# 2. USER: MAKE A PAYMENT (live review)
# ==================================================

elif page == "Make a Payment":
    page_head("Make a Payment",
              "Scored against your personal baseline before it leaves your card.",
              "Real-time scoring active")

    base = detector.baseline(user_id)
    st.info(
        f"Your regular average payment: {money(base['mean'])} · typical range "
        f"{money(base['mean'] - 2 * base['std'])} – "
        f"{money(base['mean'] + 2 * base['std'])} · from {base['count']} "
        f"past payments"
    )

    left, right = st.columns([1.05, 1], gap="large")

    with left:
        section("Pay from", "FADE Signature · ending 4271")
        card_vis(username.upper(), money(base["mean"]))

        section("Payment Details")
        recipient = st.text_input("Recipient / payee", placeholder="e.g. Amazon Pay",
                                  icon=":material/store:")
        amount = st.number_input("Amount (₹)", min_value=0.0, value=0.0, step=100.0,
                                 format="%.2f", icon=":material/payments:")

        section("Where this sits vs your average")
        gauge_panel(amount, base)

        pay_clicked = st.button("Pay Now", icon=":material/lock:", width="stretch")

        if pay_clicked:
            if not str(recipient).strip():
                st.warning("Enter a recipient for this payment.")
            elif amount <= 0:
                st.warning("Enter an amount greater than zero.")
            else:
                decision = detector.evaluate(user_id, float(amount))
                status = detector.record_payment(
                    user_id, decision, float(amount), str(recipient).strip()
                )
                st.session_state["receipt"] = {
                    "decision": decision,
                    "amount": float(amount),
                    "recipient": str(recipient).strip(),
                    "status": status,
                    "reference": f"TX-{datetime.now():%Y%m%d%H%M%S}",
                    "when": datetime.now().strftime("%d %b %Y · %H:%M:%S"),
                }
                st.rerun()

    with right:
        section("Live Review", "what the engine sees right now")
        if amount and amount > 0:
            live = detector.evaluate(user_id, float(amount))
            label = {ALLOW: "Approve", REVIEW: "Hold", BLOCK: "Decline"}[live.decision]
            verdict_box(live.decision, f"Projected: {label}", live.reason)
            st.write(f"**Your average:** {money(live.mean)}")
            st.write(f"**This payment:** {money(amount)}")
            st.write(f"**Deviation:** {live.deviation_pct:+.1f}% "
                     f"({live.z_score:+.2f}σ)")
            st.write(f"**Baseline:** {live.history_count} payments")
        else:
            st.info("Enter an amount to see the live fraud verdict before you pay.")

        section("How your payment is guarded")
        st.caption("Approve — within 2.0σ and 1.75x of your average")
        st.caption("Hold — beyond 2.0σ or 1.75x of your average")
        st.caption("Decline — beyond 3.0σ or 3x of your average")
        st.caption("Held & declined payments raise Threat Center alerts automatically.")

    # Receipt of the last executed payment
    rc = st.session_state.get("receipt")
    if rc:
        section("Receipt", rc["when"])
        title = {ALLOW: "Payment Approved", REVIEW: "Payment Held",
                 BLOCK: "Payment Declined"}[rc["decision"].decision]
        outcome = {
            ALLOW: f"Settled successfully. {rc['decision'].reason}",
            REVIEW: "NOT executed — queued for security verification. "
                    "An alert was added to the Threat Center. "
                    + rc["decision"].reason,
            BLOCK: "NOT executed — blocked to prevent fraud. A CRITICAL alert "
                   "was added to the Threat Center. " + rc["decision"].reason,
        }[rc["decision"].decision]
        verdict_box(rc["decision"].decision, title, outcome)
        receipt_table(rc)


# ==================================================
# 3. USER: MY TRANSACTIONS
# ==================================================

elif page == "My Transactions":
    page_head("My Transactions",
              "Every payment, scored and labelled by the fraud engine.")

    my_tx = get_transactions(user_id)
    approved_total = sum(tx[2] for tx in my_tx if tx[5] == "SUCCESS")
    flagged = sum(1 for tx in my_tx if tx[5] == "FLAGGED")
    blocked = sum(1 for tx in my_tx if tx[5] == "BLOCKED")

    tiles([
        ("Total Payments", str(len(my_tx)), "all recorded attempts"),
        ("Approved Value", money(approved_total), "successfully settled"),
        ("Held for Review", str(flagged), "awaiting verification"),
        ("Declined", str(blocked), "blocked by fraud shield"),
    ])

    section("Filter")
    tx_filter = st.selectbox(
        "Show", ["All", "Approved only", "Held for review", "Declined only"],
    )
    wanted = {
        "Approved only": "SUCCESS",
        "Held for review": "FLAGGED",
        "Declined only": "BLOCKED",
    }.get(tx_filter)
    shown = [tx for tx in my_tx if wanted is None or tx[5] == wanted]

    section("Ledger", f"{len(shown)} record(s)")
    display_table(shown, TRANSACTION_COLUMNS, "No transactions match this filter.")


# ==================================================
# 4. USER: SECURITY ALERTS (own account only)
# ==================================================

elif page == "Security Alerts":
    page_head("Security Alerts",
              "Attacks and fraud attempts detected on YOUR account.",
              "Scoped to your account only")

    my_threats = [t for t in threats if t[1] == user_id]
    my_logs = [l for l in login_logs if l[1] == user_id]
    my_open = sum(1 for t in my_threats if str(t[6]).upper() == "OPEN")
    my_high = sum(1 for t in my_threats
                  if str(t[3]).upper() in ("HIGH", "CRITICAL"))
    my_lockouts = sum(1 for t in my_threats if t[2] == "BRUTE FORCE ATTACK")
    my_failed_logins = sum(1 for l in my_logs if str(l[3]).upper() == "FAILED")

    tiles([
        ("Alerts On Your Account", str(len(my_threats)), "detected by the shields"),
        ("Open", str(my_open), "awaiting resolution"),
        ("High / Critical", str(my_high), "severity HIGH or above"),
        ("Account Lockouts", str(my_lockouts), "brute-force auto-locks"),
    ])

    if not my_threats:
        st.success(
            "All Clear — no security threats have been detected on your "
            "account. Both shields are active and watching."
        )
    else:
        section("Threats On Your Account",
                f"{len(my_threats)} alert(s) · raised automatically")
        display_table(my_threats, THREAT_COLUMNS, "No threats on your account.")

        st.info(
            "What these alerts mean: "
            "BRUTE FORCE ATTACK — someone failed your password "
            f"{MAX_FAILED_ATTEMPTS}+ times; your account was auto-locked for "
            f"{LOCKOUT_MINUTES} minutes. "
            "MULTIPLE FAILED LOGINS — failures are climbing, lockout is one "
            "attempt away. "
            "BLOCKED FRAUDULENT PAYMENT — a payment far outside your baseline "
            "was declined before any money moved. "
            "SUSPICIOUS PAYMENT — a payment outside your usual range was held "
            "for verification instead of executed. "
            "Alerts are raised automatically; your security team resolves them "
            "in the Threat Center."
        )

    section("Login Activity On Your Account",
            f"{my_failed_logins} failed attempt(s) recorded")
    display_table(my_logs, LOGIN_COLUMNS, "No login events on your account.")


# ==================================================
# 5. ADMIN: OVERVIEW
# ==================================================

elif page == "Overview":
    page_head("Overview",
              f"Signed in as {username} · every counter updates automatically.",
              "Auto-protection active · SOC view")

    open_threats = sum(1 for t in threats if str(t[6]).upper() == "OPEN")
    high_threats = sum(1 for t in threats if str(t[3]).upper() in ("HIGH", "CRITICAL"))
    blocked_payments = sum(1 for t in all_transactions if t[5] == "BLOCKED")
    flagged_payments = sum(1 for t in all_transactions if t[5] == "FLAGGED")
    locked_accounts = get_locked_accounts()
    since = (datetime.now() - timedelta(hours=24)).isoformat()
    failed_24h = count_failed_logins(since=since)

    tiles([
        ("Open Threats", str(open_threats), "awaiting triage"),
        ("High / Critical", str(high_threats), "severity HIGH or above"),
        ("Blocked Payments", str(blocked_payments), "declined by fraud shield"),
        ("Failed Logins (24h)", str(failed_24h), "across all accounts"),
        ("Held Payments", str(flagged_payments), "pending verification"),
        ("Locked Accounts", str(len(locked_accounts)), "auto-locked users"),
        ("Network Attacks",
         str(sum(1 for t in threats if t[2] == "NETWORK BRUTE FORCE ATTACK")),
         "IP-based brute force"),
        ("Resolved Threats",
         str(sum(1 for t in threats if str(t[6]).upper() == "RESOLVED")),
         "closed by the SOC"),
    ])

    left, right = st.columns(2, gap="large")
    with left:
        section("Threat Severity")
        if threats:
            severity_counts = {}
            for threat in threats:
                sev = str(threat[3]).upper()
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
            chart_df = pd.DataFrame(list(severity_counts.items()),
                                    columns=["Severity", "Count"])
            st.bar_chart(chart_df.set_index("Severity"), height=320)
        else:
            st.info("No threats recorded yet.")

    with right:
        section("Recent Threats")
        display_table(threats[:6], THREAT_COLUMNS, "No threats recorded.")

    section("Protection Is Fully Automatic", "no human required")
    st.info(
        f"Brute-force / credential-stuffing response — every login attempt is "
        f"gated before password verification; failed-attempt counters run per "
        f"account and per IP. At {MAX_FAILED_ATTEMPTS} failures the account "
        f"locks for {LOCKOUT_MINUTES} min; at {IP_FAILURE_THRESHOLD} failures "
        f"from one IP in {IP_WINDOW_MINUTES} min, that network is blocked for "
        f"{IP_BLOCK_MINUTES} min. Threats are raised automatically. "
        f"Payment fraud response — each payment is z-scored against the "
        f"payer's own average: deviations at or beyond 2.0-sigma are held, "
        f"at or beyond 3.0-sigma or 3x the average are declined; both raise "
        f"threats automatically."
    )

    section("Recent Authentication Events")
    display_table(login_logs[:6], LOGIN_COLUMNS, "No login events recorded.")


# ==================================================
# 6. ADMIN: THREAT CENTER
# ==================================================

elif page == "Threat Center":
    page_head("Threat Center",
              "Detection already runs on every event — triage and response "
              "live here.", "Triage mode")

    col_a, col_b = st.columns([1, 1], gap="large")

    with col_a:
        section("Full-History Re-Scan", "backfill alerts from historical logs")
        if st.button("Run Re-Scan", icon=":material/search:", key="run_detection"):
            try:
                alerts_created = detect_repeated_failed_logins(threshold=3)
                if alerts_created > 0:
                    flash("success", f"Created {alerts_created} new threat alert(s).")
                    st.rerun()
                else:
                    st.info("Re-scan complete — no missing alerts found.")
            except Exception as error:
                st.error(f"Detection failed: {error}")

    with col_b:
        section("Locked Accounts", "auto-locked by brute-force shield")
        locked = get_locked_accounts()
        if locked:
            st.error(f"{len(locked)} account(s) currently locked")
        else:
            st.success("No accounts are currently locked.")

    if locked:
        display_table(
            locked,
            ["User ID", "Username", "Role", "Failed Attempts", "Locked Until"],
            "No accounts are currently locked.",
        )
        with st.form("unlock_form"):
            lock_ids = [row[0] for row in locked]
            lock_names = {row[0]: row[1] for row in locked}
            selected = st.selectbox(
                "Unlock account", lock_ids,
                format_func=lambda i: f"{lock_names[i]} (ID {i})",
            )
            if st.form_submit_button("Unlock Account",
                                     icon=":material/lock_open:"):
                unlock_account(selected)
                flash("success",
                      f"Account '{lock_names[selected]}' unlocked — failure counter reset.")
                st.rerun()

    section("Record a Threat", "manual escalation")
    with st.form("manual_threat_form"):
        users = get_all_users()
        user_choices = {f"{u[1]} (ID {u[0]})": u[0] for u in users}
        chosen = st.selectbox("User", list(user_choices.keys()))
        threat_type = st.selectbox(
            "Threat Type",
            ["Multiple Failed Logins", "BRUTE FORCE ATTACK",
             "NETWORK BRUTE FORCE ATTACK", "SUSPICIOUS PAYMENT",
             "BLOCKED FRAUDULENT PAYMENT", "Unusual Activity", "Other"],
        )
        severity = st.selectbox("Severity", ["LOW", "MEDIUM", "HIGH", "CRITICAL"])
        description = st.text_area("Description")
        if st.form_submit_button("Record Threat", icon=":material/add_alert:"):
            try:
                add_threat(user_choices[chosen], threat_type, severity, description)
                flash("success", "Threat recorded.")
                st.rerun()
            except Exception as error:
                st.error(f"Could not record threat: {error}")

    section("All Threats", "filter, then update status")
    c1, c2 = st.columns(2)
    status_filter = c1.selectbox("Status", ["ALL", "OPEN", "INVESTIGATING", "RESOLVED"],
                                 index=1)
    severity_filter = c2.selectbox("Severity", ["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"])

    filtered = list(threats)
    if status_filter != "ALL":
        filtered = [t for t in filtered if str(t[6]).upper() == status_filter]
    if severity_filter != "ALL":
        filtered = [t for t in filtered if str(t[3]).upper() == severity_filter]

    display_table(filtered, THREAT_COLUMNS, "No threats match this filter.")

    if threats:
        with st.form("update_status_form"):
            threat_ids = [t[0] for t in threats]
            selected_id = st.selectbox("Threat ID", threat_ids)
            new_status = st.selectbox("Status", ["OPEN", "INVESTIGATING", "RESOLVED"])
            if st.form_submit_button("Update Status", icon=":material/task:"):
                try:
                    update_threat_status(selected_id, new_status)
                    flash("success", "Threat status updated.")
                    st.rerun()
                except Exception as error:
                    st.error(f"Could not update status: {error}")


# ==================================================
# 7. ADMIN: AUTHENTICATION LOGS
# ==================================================

elif page == "Authentication Logs":
    page_head("Authentication Logs",
              "Simulated events run through the same detector as the real "
              "login page.", "Audit trail")

    users = get_all_users()
    user_map = {f"{u[1]} (ID {u[0]})": u[0] for u in users}

    section("Simulate a Login Event", "thresholds fire automatically")
    with st.form("login_event_form"):
        chosen = st.selectbox("Account", list(user_map.keys()))
        status = st.selectbox("Login Result", ["FAILED", "SUCCESS"])
        ip_address = st.text_input("IP Address", value="203.0.113.50",
                                   icon=":material/router:")
        device = st.text_input("Device", value="Simulated Device",
                               icon=":material/devices:")
        if st.form_submit_button("Record Event", icon=":material/play_arrow:"):
            try:
                row = get_user(chosen.split(" (ID")[0])
                if status == "FAILED":
                    actions = register_failed_login(row, ip_address, device)
                    msgs = ["FAILED event recorded."]
                    if actions["locked_account"]:
                        msgs.append(f"Account AUTO-LOCKED after {MAX_FAILED_ATTEMPTS} failures.")
                    if actions["threats_created"]:
                        msgs.append(f"{actions['threats_created']} threat(s) raised automatically.")
                    flash("success", " ".join(msgs))
                else:
                    register_successful_login(row, ip_address, device)
                    flash("success", "SUCCESS event recorded (counters reset).")
                st.rerun()
            except Exception as error:
                st.error(f"Could not record event: {error}")

    section("Failed Attempts by Network",
            f"rolling {IP_WINDOW_MINUTES}-min window · block at {IP_FAILURE_THRESHOLD}")
    recent_cutoff = (datetime.now() - timedelta(minutes=IP_WINDOW_MINUTES)).isoformat()
    recent_fails = [l for l in login_logs if str(l[3]).upper() == "FAILED"
                    and l[2] >= recent_cutoff]
    if recent_fails:
        per_ip = {}
        for log in recent_fails:
            per_ip[log[4]] = per_ip.get(log[4], 0) + 1
        rows = sorted(per_ip.items(), key=lambda kv: -kv[1])
        net_df = pd.DataFrame(
            [(ip, cnt, "BLOCKED" if cnt >= IP_FAILURE_THRESHOLD else "monitoring")
             for ip, cnt in rows],
            columns=["IP Address", "Failed (5 min)", "State"],
        )
        st.dataframe(net_df, width="stretch", hide_index=True)
    else:
        st.info("No failed attempts in the current window.")

    section("Recorded Events", f"{len(login_logs)} event(s)")
    display_table(login_logs, LOGIN_COLUMNS, "No login events recorded.")


# ==================================================
# 8. ADMIN: FRAUD ACTIVITY (read-only — attacks only)
# ==================================================

elif page == "Fraud Activity":
    page_head("Fraud Activity",
              "Read-only: payments flagged by the fraud shield. Admins handle "
              "attacks and threats — never create transactions.",
              "Read-only")

    blocked_tx = [t for t in all_transactions if t[5] == "BLOCKED"]
    held_tx = [t for t in all_transactions if t[5] == "FLAGGED"]
    FRAUD_TYPES = ("SUSPICIOUS PAYMENT", "BLOCKED FRAUDULENT PAYMENT",
                   "FINANCIAL_FRAUD")
    fraud_threats = [t for t in threats if t[2] in FRAUD_TYPES]
    open_fraud = sum(1 for t in fraud_threats if str(t[6]).upper() == "OPEN")

    tiles([
        ("Declined Payments", str(len(blocked_tx)), "blocked before money moved"),
        ("Held Payments", str(len(held_tx)), "awaiting verification"),
        ("Payment-Fraud Threats", str(len(fraud_threats)), "raised automatically"),
        ("Open Fraud Alerts", str(open_fraud), "need your triage"),
    ])

    section("Declined Payments", "fraud shield blocked these")
    display_table(blocked_tx, TRANSACTION_COLUMNS,
                  "No declined payments — the shield has caught nothing yet.")

    section("Held Payments", "queued for verification")
    display_table(held_tx, TRANSACTION_COLUMNS,
                  "No payments are currently held for review.")

    section("Payment-Fraud Threats", "triage these in the Threat Center")
    display_table(fraud_threats, THREAT_COLUMNS,
                  "No payment-fraud threats recorded.")

    st.info(
        "Scope note — this page is read-only. Creating, approving or editing "
        "payments is reserved for the account holder on their own "
        "Make a Payment page; the administrator's role is to handle attacks "
        "and resolve security threats."
    )
