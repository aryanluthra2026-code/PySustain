import streamlit as st
import pandas as pd

from data import (
    get_threats,
    get_login_logs,
    get_transactions,
    add_threat,
    update_threat_status,
    add_transaction,
)

from detection import detect_repeated_failed_logins
from auth import show_login_page, logout


# ==================================================
# PAGE CONFIGURATION
# ==================================================

st.set_page_config(
    page_title="FADE | Security Dashboard",
    layout="wide",
)


# ==================================================
# GLOBAL STYLING / THEME
# ==================================================

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Barlow+Semi+Condensed:wght@500;600;700;800;900&family=IBM+Plex+Mono:wght@400;500;600&display=swap');

.stApp {
    background-color: #0b0f19;
    color: #e5e7eb;
    font-family: 'IBM Plex Mono', monospace;
}

[data-testid="stHeader"] {
    background: transparent;
}

[data-testid="stSidebar"] {
    background-color: #111827;
    border-right: 1px solid #293449;
}

[data-testid="stSidebar"] * {
    font-family: 'IBM Plex Mono', monospace;
}

h1, h2, h3 {
    font-family: 'Barlow Semi Condensed', sans-serif;
    font-weight: 900;
    letter-spacing: -1.5px;
    text-transform: uppercase;
    color: #f3f4f6;
}

h1 {
    font-size: clamp(2.5rem, 6vw, 5rem) !important;
    line-height: 0.95 !important;
}

p, label, [data-testid="stCaptionContainer"] {
    color: #91879B;
}

hr {
    border-color: #293449;
}

[data-testid="stMetric"] {
    background-color: #151c2c;
    border: 1px solid #293449;
    border-radius: 12px;
    padding: 18px;
}

[data-testid="stMetricLabel"] {
    color: #91879B !important;
    font-family: 'IBM Plex Mono', monospace !important;
    text-transform: uppercase;
    font-size: 0.72rem !important;
}

[data-testid="stMetricValue"] {
    color: #A855F7 !important;
    font-weight: 600 !important;
}

.stButton > button {
    background: #7026A6;
    color: white;
    border: 1px solid #A855F7;
    border-radius: 2px;
    font-family: 'IBM Plex Mono', monospace;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.04em;
}

.stButton > button:hover {
    background: #8D35C4;
    border-color: #D8B4FE;
    color: white;
}

input, textarea {
    background: #0C0910 !important;
    color: #F0EAF5 !important;
    border-radius: 2px !important;
}

[data-testid="stForm"] {
    background: #151c2c;
    border: 1px solid #293449;
    border-radius: 10px;
    padding: 1.5rem;
}

#MainMenu, footer {
    visibility: hidden;
}
</style>
""", unsafe_allow_html=True)


# ==================================================
# AUTHENTICATION GATE
# ==================================================

if not st.session_state.get("authenticated", False):
    show_login_page()
    st.stop()


username = st.session_state.get("username", "User")
role = str(st.session_state.get("role", "USER")).upper()


# ==================================================
# SIDEBAR
# ==================================================

st.sidebar.markdown(
    """<div style="font-family: 'Barlow Semi Condensed', sans-serif; font-size: 40px; font-weight: 900; font-style: italic; letter-spacing: -1.5px; text-transform: uppercase;">FADE</div>""",
    unsafe_allow_html=True,
)
st.sidebar.caption("Fraud Analysis & Detection Engine")
st.sidebar.divider()

st.sidebar.write(f"Signed in as **{username}**")
st.sidebar.write(f"Role: **{role}**")

if st.sidebar.button("Log Out", use_container_width=True):
    logout()

st.sidebar.divider()

if role == "ADMIN":
    available_pages = [
        "Overview",
        "Threat Center",
        "Authentication Logs",
        "Transaction Monitor",
    ]
else:
    available_pages = [
        "Overview",
        "My Transactions",
    ]

page = st.sidebar.radio("Navigation", available_pages)

st.sidebar.divider()
st.sidebar.caption("FADE Prototype")


# ==================================================
# TABLE HELPERS
# ==================================================

LOGIN_COLUMNS = ["Log ID", "User ID", "Status", "IP Address", "Device", "Timestamp"]
THREAT_COLUMNS = ["Threat ID", "User ID", "Threat Type", "Severity", "Description", "Created At", "Status"]
TRANSACTION_COLUMNS = ["Transaction ID", "User ID", "Amount", "Recipient", "Status", "Timestamp"]


def display_table(data, columns, empty_message):
    if not data:
        st.info(empty_message)
        return
    try:
        df = pd.DataFrame(data, columns=columns)
        st.dataframe(df, use_container_width=True, hide_index=True)
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
# 1. USER OVERVIEW
# ==================================================

if page == "Overview":
    st.title("Security Overview")
    st.caption(f"Welcome back, {username}.")

    if role == "ADMIN":
        total_threats = len(threats)
        open_threats = sum(1 for t in threats if str(t[6]).upper() == "OPEN")
        high_threats = sum(1 for t in threats if str(t[3]).upper() == "HIGH")

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total Threats", total_threats)
        col2.metric("Open Threats", open_threats)
        col3.metric("High-Severity Threats", high_threats)
        col4.metric("Transactions", len(all_transactions))

        left, right = st.columns(2)
        with left:
            st.subheader("Threat Severity")
            if threats:
                severity_counts = {}
                for threat in threats:
                    sev = str(threat[3]).upper()
                    severity_counts[sev] = severity_counts.get(sev, 0) + 1
                chart_df = pd.DataFrame(list(severity_counts.items()), columns=["Severity", "Count"])
                st.bar_chart(chart_df.set_index("Severity"))
            else:
                st.info("No threats recorded yet.")

        with right:
            st.subheader("Recent Threats")
            display_table(threats[::-1][:5], THREAT_COLUMNS, "No threats recorded.")

        st.subheader("Recent Authentication Events")
        display_table(login_logs[:5], LOGIN_COLUMNS, "No login events recorded.")

    else:
        st.info("Standard user account view.")
        my_transactions = [tx for tx in all_transactions if tx[1] == st.session_state["user_id"]]
        st.metric("My Transactions", len(my_transactions))
        display_table(my_transactions[::-1], TRANSACTION_COLUMNS, "You have no transactions recorded.")


# ==================================================
# 2. ADMIN: THREAT CENTER
# ==================================================

elif page == "Threat Center" and role == "ADMIN":
    st.title("Threat Center")

    st.subheader("Failed-Login Detection")
    if st.button("Run Failed-Login Detection", key="run_detection", type="primary"):
        try:
            alerts_created = detect_repeated_failed_logins(threshold=3)
            if alerts_created > 0:
                st.success(f"Created {alerts_created} new threat alert(s).")
                st.rerun()
            else:
                st.info("Detection completed, but no new alerts were created.")
        except Exception as error:
            st.error(f"Detection failed: {error}")

    st.divider()
    st.subheader("Record a Threat")

    with st.form("manual_threat_form"):
        threat_user_id = st.number_input("User ID", min_value=1, step=1, value=1)
        threat_type = st.selectbox("Threat Type", ["Multiple Failed Logins", "Suspicious Transaction", "Unusual Activity", "Other"])
        severity = st.selectbox("Severity", ["LOW", "MEDIUM", "HIGH", "CRITICAL"])
        description = st.text_area("Description")
        submitted = st.form_submit_button("Record Threat")

        if submitted:
            try:
                add_threat(int(threat_user_id), threat_type, severity, description)
                st.success("Threat recorded.")
                st.rerun()
            except Exception as error:
                st.error(f"Could not record threat: {error}")

    st.divider()
    st.subheader("All Threats & Filters")

    current_threats = get_threats()
    status_filter = st.selectbox("Filter by status", ["ALL", "OPEN", "INVESTIGATING", "RESOLVED"])

    filtered_threats = current_threats[::-1]
    if status_filter != "ALL":
        filtered_threats = [t for t in filtered_threats if str(t[6]).upper() == status_filter]

    display_table(filtered_threats, THREAT_COLUMNS, "No threats match this filter.")

    if current_threats:
        st.divider()
        st.subheader("Update Threat Status")
        with st.form("update_status_form"):
            threat_ids = [t[0] for t in current_threats]
            selected_id = st.selectbox("Threat ID", threat_ids)
            new_status = st.selectbox("Status", ["OPEN", "INVESTIGATING", "RESOLVED"])
            update_submitted = st.form_submit_button("Update Status")

            if update_submitted:
                try:
                    update_threat_status(selected_id, new_status)
                    st.success("Threat status updated.")
                    st.rerun()
                except Exception as error:
                    st.error(f"Could not update status: {error}")


# ==================================================
# 3. ADMIN: AUTHENTICATION LOGS
# ==================================================

elif page == "Authentication Logs" and role == "ADMIN":
    st.title("Authentication Logs")
    st.subheader("Simulate a Login Event")

    with st.form("login_event_form"):
        user_id = st.number_input("User ID", min_value=1, step=1, value=1)
        status = st.selectbox("Login Result", ["SUCCESS", "FAILED"])
        ip_address = st.text_input("IP Address", value="127.0.0.1")
        device = st.text_input("Device", value="Local Test Device")
        submitted = st.form_submit_button("Record Event")

        if submitted:
            try:
                from data import record_login
                record_login(int(user_id), status, ip_address, device)
                st.success(f"{status} event recorded.")
                st.rerun()
            except Exception as error:
                st.error(f"Could not record event: {error}")

    st.divider()
    st.subheader("Recorded Events")
    display_table(get_login_logs(), LOGIN_COLUMNS, "No login events recorded.")


# ==================================================
# 4. ADMIN: TRANSACTION MONITOR
# ==================================================

elif page == "Transaction Monitor" and role == "ADMIN":
    st.title("Transaction Monitor")

    with st.form("transaction_form"):
        user_id = st.number_input("User ID", min_value=1, step=1, value=1, key="transaction_user_id")
        amount = st.number_input("Amount", min_value=0.01, value=500.0, step=100.0)
        recipient = st.text_input("Recipient")
        status = st.selectbox("Transaction Status", ["SUCCESS", "FAILED", "FLAGGED"])
        submitted = st.form_submit_button("Record Transaction")

        if submitted:
            try:
                add_transaction(int(user_id), float(amount), recipient, status)
                st.success("Transaction recorded.")
                st.rerun()
            except Exception as error:
                st.error(f"Could not record transaction: {error}")

    st.divider()
    display_table(get_transactions()[::-1], TRANSACTION_COLUMNS, "No transactions recorded.")


# ==================================================
# 5. USER: MY TRANSACTIONS
# ==================================================

elif page == "My Transactions":
    st.title("My Transactions")
    my_transactions = [tx for tx in get_transactions() if tx[1] == st.session_state["user_id"]]
    display_table(my_transactions[::-1], TRANSACTION_COLUMNS, "You have no transactions recorded.")
