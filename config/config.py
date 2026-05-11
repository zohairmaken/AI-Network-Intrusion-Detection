# =============================================================================
# config/config.py
# Global configuration for AI-Powered NIDS
# =============================================================================

import os

# ─── Application Settings ────────────────────────────────────────────────────
APP_NAME = "AI-Powered Network Intrusion Detection System"
APP_VERSION = "1.0.0"
APP_AUTHOR = "NIDS Project Team"
DEBUG_MODE = False

# ─── Network Monitoring Settings ─────────────────────────────────────────────
PACKET_CAPTURE_TIMEOUT = 30        # seconds per capture session
MAX_PACKETS_PER_SESSION = 1000     # max packets to capture per run
PACKET_BUFFER_SIZE = 100           # packets before batch processing
SNIFF_INTERFACE = None             # None = auto-detect default interface
PROMISCUOUS_MODE = True

# ─── Machine Learning Settings ────────────────────────────────────────────────
RANDOM_SEED = 42
TEST_SIZE = 0.25
VALIDATION_SIZE = 0.1
N_ESTIMATORS = 200                 # Random Forest trees
MAX_DEPTH = 20
MIN_SAMPLES_SPLIT = 5
N_JOBS = -1                        # use all CPU cores

# ─── Alert Settings ───────────────────────────────────────────────────────────
ALERT_THRESHOLD_HIGH = 0.85        # confidence above this = HIGH severity
ALERT_THRESHOLD_MEDIUM = 0.60      # confidence above this = MEDIUM severity
MAX_ALERTS_DISPLAY = 50            # max alerts shown in dashboard

# ─── Email Alert Settings (optional) ─────────────────────────────────────────
EMAIL_ALERTS_ENABLED = False
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SENDER_EMAIL = "nids.alerts@example.com"
RECEIVER_EMAIL = "admin@example.com"
EMAIL_APP_PASSWORD = ""            # Gmail App Password

# ─── Dashboard Settings ───────────────────────────────────────────────────────
DASHBOARD_REFRESH_INTERVAL = 3    # seconds
CHART_HEIGHT = 350
MAX_LOG_ROWS_DISPLAY = 100
LIVE_GRAPH_POINTS = 60            # data points shown in live graph

# ─── Threat Classification Labels ─────────────────────────────────────────────
ATTACK_LABELS = {
    0: "NORMAL",
    1: "DoS Attack",
    2: "Port Scan",
    3: "Brute Force",
    4: "Suspicious Activity"
}

SEVERITY_COLORS = {
    "NORMAL": "#00ff88",
    "DoS Attack": "#ff4444",
    "Port Scan": "#ff8800",
    "Brute Force": "#ff2266",
    "Suspicious Activity": "#ffdd00"
}

# ─── Blacklist Settings ───────────────────────────────────────────────────────
BLACKLIST_AUTO_ADD = True          # auto-add attacker IPs to blacklist
BLACKLIST_THRESHOLD = 3            # attacks before auto-blacklist

# ─── Authentication ───────────────────────────────────────────────────────────
AUTH_ENABLED = True
DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "nids@2024"     # Change in production
SESSION_TIMEOUT = 3600             # seconds
