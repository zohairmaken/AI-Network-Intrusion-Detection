# =============================================================================
# app/authentication.py
# Secure session-based authentication for the NIDS dashboard
# =============================================================================

import hashlib
import time
import streamlit as st
from config.config import DEFAULT_USERNAME, DEFAULT_PASSWORD, SESSION_TIMEOUT, AUTH_ENABLED


def _hash_password(password: str) -> str:
    """Return SHA-256 hash of a password."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


# ─── In-memory user store (extend to DB for production) ─────────────────────
_USERS = {
    DEFAULT_USERNAME: _hash_password(DEFAULT_PASSWORD),
    "analyst":        _hash_password("analyst@2024"),
    "viewer":         _hash_password("view@2024")
}

_USER_ROLES = {
    DEFAULT_USERNAME: "Administrator",
    "analyst":        "Security Analyst",
    "viewer":         "Read-Only Viewer"
}


def verify_credentials(username: str, password: str) -> bool:
    """Return True if credentials are valid."""
    hashed = _hash_password(password)
    return _USERS.get(username) == hashed


def get_role(username: str) -> str:
    """Return role string for a username."""
    return _USER_ROLES.get(username, "Unknown")


def is_session_valid() -> bool:
    """Check if current Streamlit session is authenticated and not expired."""
    if not AUTH_ENABLED:
        return True
    if not st.session_state.get("authenticated", False):
        return False
    login_time = st.session_state.get("login_time", 0)
    if time.time() - login_time > SESSION_TIMEOUT:
        st.session_state["authenticated"] = False
        return False
    return True


def login(username: str, password: str) -> bool:
    """
    Attempt login and update session state.

    Returns:
        True on success, False on failure.
    """
    if verify_credentials(username, password):
        st.session_state["authenticated"] = True
        st.session_state["username"]      = username
        st.session_state["role"]          = get_role(username)
        st.session_state["login_time"]    = time.time()
        return True
    return False


def logout():
    """Clear authentication session state."""
    for key in ["authenticated", "username", "role", "login_time"]:
        st.session_state.pop(key, None)


def render_login_page():
    """
    Render a styled login page.
    Call this from the main app when the user is not authenticated.
    """
    # Custom CSS for login page
    st.markdown("""
    <style>
    .login-container {
        max-width: 420px;
        margin: 60px auto;
        padding: 40px;
        background: linear-gradient(135deg, #121929 0%, #0d1b2a 100%);
        border: 1px solid #1e3a5f;
        border-radius: 16px;
        box-shadow: 0 0 40px rgba(0,170,255,0.15);
    }
    .login-title {
        font-size: 1.8rem;
        font-weight: 800;
        color: #00aaff;
        text-align: center;
        margin-bottom: 6px;
        letter-spacing: -0.5px;
    }
    .login-subtitle {
        font-size: 0.85rem;
        color: #64748b;
        text-align: center;
        margin-bottom: 30px;
    }
    .login-badge {
        display: inline-block;
        background: rgba(0,170,255,0.12);
        border: 1px solid #00aaff44;
        border-radius: 20px;
        padding: 4px 14px;
        font-size: 0.75rem;
        color: #00aaff;
        margin-bottom: 20px;
    }
    </style>
    """, unsafe_allow_html=True)

    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown('<div class="login-title">🛡 NIDS Portal</div>', unsafe_allow_html=True)
        st.markdown(
            '<div class="login-subtitle">AI-Powered Network Intrusion Detection System</div>',
            unsafe_allow_html=True
        )
        st.markdown('<div style="text-align:center"><span class="login-badge">🔒 Secure Access Required</span></div>', unsafe_allow_html=True)

        with st.form("login_form", clear_on_submit=False):
            username = st.text_input("👤 Username", placeholder="Enter username")
            password = st.text_input("🔑 Password", type="password", placeholder="Enter password")
            submitted = st.form_submit_button("Sign In →", use_container_width=True)

            if submitted:
                if not username or not password:
                    st.error("Please enter both username and password.")
                elif login(username, password):
                    st.success(f"Welcome, {username}! Redirecting...")
                    time.sleep(0.5)
                    st.rerun()
                else:
                    st.error("Invalid credentials. Please try again.")

        st.caption("Default: admin / nids@2024")


def require_auth(func):
    """
    Decorator: render login page if user is not authenticated.
    Usage: @require_auth above any Streamlit page function.
    """
    def wrapper(*args, **kwargs):
        if not is_session_valid():
            render_login_page()
        else:
            func(*args, **kwargs)
    return wrapper
