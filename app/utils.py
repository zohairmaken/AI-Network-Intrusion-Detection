# =============================================================================
# app/utils.py
# Helper utility functions for the NIDS application
# =============================================================================

import os
import csv
import json
import time
import socket
import platform
import psutil
import pandas as pd
from datetime import datetime
from typing import Optional

import core.logger as log
from config.paths import ATTACK_LOG_PATH, SAMPLE_TRAFFIC_PATH
from config.constants import PROTOCOL_MAP, FEATURE_COLUMNS
from config.config import SEVERITY_COLORS


# ─── Network Utilities ────────────────────────────────────────────────────────

def get_local_ip() -> str:
    """Return the local machine's IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def get_hostname() -> str:
    """Return the machine's hostname."""
    return socket.gethostname()


def get_network_interfaces() -> list:
    """
    Return list of available network interfaces with their IP addresses.
    """
    interfaces = []
    try:
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    interfaces.append({
                        "name": iface,
                        "ip":   addr.address,
                        "mask": addr.netmask
                    })
    except Exception as e:
        log.warning("Could not enumerate interfaces: %s", str(e))
    return interfaces


def get_system_stats() -> dict:
    """Return real-time system performance metrics."""
    try:
        cpu   = psutil.cpu_percent(interval=0.1)
        mem   = psutil.virtual_memory()
        disk  = psutil.disk_usage("/")
        net   = psutil.net_io_counters()
        return {
            "cpu_percent":    cpu,
            "memory_percent": mem.percent,
            "memory_used_gb": round(mem.used / 1e9, 2),
            "memory_total_gb":round(mem.total / 1e9, 2),
            "disk_percent":   disk.percent,
            "net_bytes_sent": net.bytes_sent,
            "net_bytes_recv": net.bytes_recv,
            "platform":       platform.system(),
            "python_version": platform.python_version()
        }
    except Exception:
        return {}


# ─── Protocol Helpers ─────────────────────────────────────────────────────────

def protocol_name(proto_num: int) -> str:
    """Convert protocol number to name string."""
    return PROTOCOL_MAP.get(int(proto_num), f"PROTO-{proto_num}")


def severity_badge_html(severity: str) -> str:
    """Return an HTML badge string for a severity level."""
    color = {
        "CRITICAL": "#ff2266",
        "HIGH":     "#ff4444",
        "MEDIUM":   "#ff8800",
        "LOW":      "#ffdd00"
    }.get(severity, "#94a3b8")
    return (
        f'<span style="background:{color}22; color:{color}; '
        f'border:1px solid {color}44; border-radius:12px; '
        f'padding:2px 10px; font-size:0.78rem; font-weight:600;">'
        f'{severity}</span>'
    )


def attack_badge_html(prediction: str) -> str:
    """Return an HTML badge for an attack type."""
    color = SEVERITY_COLORS.get(prediction, "#94a3b8")
    return (
        f'<span style="background:{color}22; color:{color}; '
        f'border:1px solid {color}44; border-radius:12px; '
        f'padding:2px 10px; font-size:0.78rem; font-weight:600;">'
        f'{prediction}</span>'
    )


# ─── CSV / Data Utilities ─────────────────────────────────────────────────────

def load_attack_logs_df() -> pd.DataFrame:
    """Load attack logs CSV into a DataFrame."""
    if not os.path.exists(ATTACK_LOG_PATH) or os.path.getsize(ATTACK_LOG_PATH) == 0:
        return pd.DataFrame()
    try:
        df = pd.read_csv(ATTACK_LOG_PATH)
        return df
    except Exception as e:
        log.error("Failed to load attack logs: %s", str(e))
        return pd.DataFrame()


def load_sample_traffic() -> list:
    """
    Load sample traffic rows from CSV for demo mode.

    Returns:
        List of dicts with feature values
    """
    if not os.path.exists(SAMPLE_TRAFFIC_PATH):
        log.warning("Sample traffic file not found: %s", SAMPLE_TRAFFIC_PATH)
        return []
    try:
        df = pd.read_csv(SAMPLE_TRAFFIC_PATH)
        return df.to_dict(orient="records")
    except Exception as e:
        log.error("Failed to load sample traffic: %s", str(e))
        return []


def export_logs_to_csv(df: pd.DataFrame, output_path: str) -> bool:
    """Export a DataFrame to CSV file."""
    try:
        df.to_csv(output_path, index=False)
        log.info("Logs exported to %s", output_path)
        return True
    except Exception as e:
        log.error("Export failed: %s", str(e))
        return False


def export_logs_to_json(df: pd.DataFrame, output_path: str) -> bool:
    """Export a DataFrame to JSON file."""
    try:
        df.to_json(output_path, orient="records", indent=2)
        log.info("Logs exported to %s (JSON)", output_path)
        return True
    except Exception as e:
        log.error("JSON export failed: %s", str(e))
        return False


# ─── Formatting Utilities ─────────────────────────────────────────────────────

def format_bytes(n: int) -> str:
    """Human-readable byte count string."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def format_duration(seconds: float) -> str:
    """Convert seconds to human-readable duration string."""
    if seconds < 60:
        return f"{int(seconds)}s"
    elif seconds < 3600:
        m, s = divmod(int(seconds), 60)
        return f"{m}m {s}s"
    else:
        h, rem = divmod(int(seconds), 3600)
        m = rem // 60
        return f"{h}h {m}m"


def timestamp_now() -> str:
    """Return ISO-formatted timestamp string."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def confidence_bar_html(confidence: float) -> str:
    """
    Render a mini HTML progress bar for confidence score.
    confidence: float 0.0–1.0
    """
    pct = round(confidence * 100, 1)
    color = "#00ff88" if pct >= 85 else "#ffdd00" if pct >= 60 else "#ff4444"
    return (
        f'<div style="background:#1e2d40; border-radius:4px; height:8px; width:100%;">'
        f'<div style="background:{color}; width:{pct}%; height:8px; border-radius:4px;"></div>'
        f'</div><small style="color:#94a3b8;">{pct}%</small>'
    )


def get_uptime_str(start_time: Optional[float]) -> str:
    """Return formatted uptime string from a start timestamp."""
    if start_time is None:
        return "Not running"
    return format_duration(time.time() - start_time)
