import hashlib

import streamlit as st

from data import get_user, record_login


def hash_password(password):
    """Match the SHA-256 hashing used by the existing database."""
    return hashlib.sha256(
        password.encode("utf-8")
    ).hexdigest()


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

    supplied_hash = hash_password(password)
    stored_hash = str(user[2])

    if supplied_hash != stored_hash:
        return False, None, "Invalid username or password."

    return True, user, "Login successful."


def show_login_page():
    """Display the login form and record login attempts."""

    st.title("FADE")
    st.subheader("Secure Login")
    st.caption("Fraud Analysis & Detection Engine")

    with st.form("fade_login_form"):
        username = st.text_input("Username")
        password = st.text_input(
            "Password",
            type="password",
        )

        submitted = st.form_submit_button(
            "Log In",
            type="primary",
            use_container_width=True,
        )

    if submitted:
        if not username.strip() or not password:
            st.warning("Enter both your username and password.")
            return

        try:
            success, user, message = authenticate(
                username,
                password,
            )

            if success:
                record_login(
                    user[0],
                    "SUCCESS",
                    "127.0.0.1",
                    "FADE Web App",
                )

                st.session_state["authenticated"] = True
                st.session_state["user_id"] = user[0]
                st.session_state["username"] = user[1]
                st.session_state["role"] = user[3]

                st.success(message)
                st.rerun()

            else:
                # If the username exists, associate the failed
                # attempt with that account for detection.
                existing_user = get_user(username.strip())

                if existing_user is not None:
                    record_login(
                        existing_user[0],
                        "FAILED",
                        "127.0.0.1",
                        "FADE Web App",
                    )

                st.error(message)

        except Exception as error:
            st.error(
                f"Login could not be completed: {error}"
            )


def logout():
    """Clear the current login session."""
    for key in (
        "authenticated",
        "user_id",
        "username",
        "role",
    ):
        st.session_state.pop(key, None)

    st.rerun()
