# =============================================================================
# config/constants.py
# Constant values used throughout the NIDS
# =============================================================================

# ─── Traffic Classes ──────────────────────────────────────────────────────────
CLASS_NORMAL = "NORMAL"
CLASS_DOS = "DoS Attack"
CLASS_PORT_SCAN = "Port Scan"
CLASS_BRUTE_FORCE = "Brute Force"
CLASS_SUSPICIOUS = "Suspicious Activity"

ALL_CLASSES = [CLASS_NORMAL, CLASS_DOS, CLASS_PORT_SCAN, CLASS_BRUTE_FORCE, CLASS_SUSPICIOUS]
ATTACK_CLASSES = [CLASS_DOS, CLASS_PORT_SCAN, CLASS_BRUTE_FORCE, CLASS_SUSPICIOUS]

# ─── Protocol Numbers ─────────────────────────────────────────────────────────
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMP = 1

PROTOCOL_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    132: "SCTP"
}

# ─── TCP Flags ────────────────────────────────────────────────────────────────
TCP_FLAG_FIN = 0x01
TCP_FLAG_SYN = 0x02
TCP_FLAG_RST = 0x04
TCP_FLAG_PSH = 0x08
TCP_FLAG_ACK = 0x10
TCP_FLAG_URG = 0x20

# ─── Well-Known Ports ─────────────────────────────────────────────────────────
PORT_SSH = 22
PORT_TELNET = 23
PORT_HTTP = 80
PORT_HTTPS = 443
PORT_FTP = 21
PORT_SMTP = 25
PORT_DNS = 53
PORT_RDP = 3389
PORT_SMB = 445

SENSITIVE_PORTS = {21, 22, 23, 25, 53, 80, 443, 445, 3389, 3306, 5432, 6379, 27017}

# ─── Severity Levels ──────────────────────────────────────────────────────────
SEVERITY_LOW = "LOW"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_HIGH = "HIGH"
SEVERITY_CRITICAL = "CRITICAL"

SEVERITY_SCORE = {
    SEVERITY_LOW: 1,
    SEVERITY_MEDIUM: 2,
    SEVERITY_HIGH: 3,
    SEVERITY_CRITICAL: 4
}

# ─── Feature Names (matching training features) ───────────────────────────────
FEATURE_COLUMNS = [
    "duration", "protocol_type", "src_port", "dst_port",
    "pkt_length", "flag_syn", "flag_ack", "flag_fin",
    "flag_rst", "flag_psh", "flag_urg", "pkt_count",
    "byte_count", "flow_rate", "inter_arrival_time",
    "is_sensitive_port", "port_scan_score", "dos_score"
]

# ─── Log CSV Headers ──────────────────────────────────────────────────────────
LOG_COLUMNS = [
    "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
    "protocol", "pkt_length", "prediction", "confidence",
    "severity", "action_taken"
]

# ─── Color Palette for UI ─────────────────────────────────────────────────────
COLOR_NORMAL = "#00ff88"
COLOR_DOS = "#ff4444"
COLOR_PORT_SCAN = "#ff8800"
COLOR_BRUTE_FORCE = "#ff2266"
COLOR_SUSPICIOUS = "#ffdd00"
COLOR_BACKGROUND = "#0a0e1a"
COLOR_CARD = "#121929"
COLOR_ACCENT = "#00aaff"

# ─── Model Performance Targets ───────────────────────────────────────────────
MIN_ACCURACY_THRESHOLD = 0.92
MIN_PRECISION_THRESHOLD = 0.90
MIN_RECALL_THRESHOLD = 0.90
