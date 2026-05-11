# =============================================================================
# core/logger.py
# Centralized logging for attacks, system events, and suspicious activity
# =============================================================================

import os
import csv
import logging
import threading
from datetime import datetime

from config.paths import ATTACK_LOG_PATH, SUSPICIOUS_LOG_PATH, SYSTEM_LOG_PATH, BLACKLIST_PATH
from config.constants import LOG_COLUMNS, SEVERITY_CRITICAL, SEVERITY_HIGH

# ─── Thread-safe lock ─────────────────────────────────────────────────────────
_log_lock = threading.Lock()

# ─── Configure Python standard logger ────────────────────────────────────────
def _setup_system_logger() -> logging.Logger:
    logger = logging.getLogger("NIDS")
    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    # File handler
    fh = logging.FileHandler(SYSTEM_LOG_PATH, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)

    if not logger.handlers:
        logger.addHandler(fh)
        logger.addHandler(ch)
    return logger


system_logger = _setup_system_logger()


# ─── Attack Log ───────────────────────────────────────────────────────────────
def _ensure_attack_log():
    """Create attack log CSV with headers if it doesn't exist."""
    if not os.path.exists(ATTACK_LOG_PATH) or os.path.getsize(ATTACK_LOG_PATH) == 0:
        with open(ATTACK_LOG_PATH, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=LOG_COLUMNS)
            writer.writeheader()


def log_attack(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
               protocol: str, pkt_length: int, prediction: str,
               confidence: float, severity: str, action: str = "LOGGED"):
    """
    Write a detected attack record to attack_logs.csv.
    Thread-safe.
    """
    _ensure_attack_log()
    record = {
        "timestamp":    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip":       src_ip,
        "dst_ip":       dst_ip,
        "src_port":     src_port,
        "dst_port":     dst_port,
        "protocol":     protocol,
        "pkt_length":   pkt_length,
        "prediction":   prediction,
        "confidence":   round(confidence, 4),
        "severity":     severity,
        "action_taken": action
    }
    with _log_lock:
        with open(ATTACK_LOG_PATH, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=LOG_COLUMNS)
            writer.writerow(record)

    # Also write to suspicious activity log if HIGH/CRITICAL
    if severity in (SEVERITY_HIGH, SEVERITY_CRITICAL):
        log_suspicious(
            f"[{severity}] {prediction} detected | "
            f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} | "
            f"Confidence: {confidence:.2%}"
        )

    system_logger.warning(
        "ATTACK DETECTED | %s | %s -> %s | Severity: %s | Conf: %.2f%%",
        prediction, src_ip, dst_ip, severity, confidence * 100
    )


def log_suspicious(message: str):
    """Write a message to suspicious_activity.log."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with _log_lock:
        with open(SUSPICIOUS_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {message}\n")


# ─── Blacklist Management ─────────────────────────────────────────────────────
def add_to_blacklist(ip: str):
    """Add an IP address to the blacklist file."""
    existing = load_blacklist()
    if ip not in existing:
        with _log_lock:
            with open(BLACKLIST_PATH, "a", encoding="utf-8") as f:
                f.write(f"{ip}\n")
        system_logger.info("IP blacklisted: %s", ip)


def load_blacklist() -> set:
    """Return the current set of blacklisted IPs."""
    if not os.path.exists(BLACKLIST_PATH):
        return set()
    with open(BLACKLIST_PATH, "r", encoding="utf-8") as f:
        return {line.strip() for line in f if line.strip()}


def is_blacklisted(ip: str) -> bool:
    """Check whether an IP is in the blacklist."""
    return ip in load_blacklist()


# ─── Attack Log Reading ───────────────────────────────────────────────────────
def read_attack_logs() -> list:
    """Return all attack log entries as a list of dicts."""
    _ensure_attack_log()
    records = []
    with _log_lock:
        with open(ATTACK_LOG_PATH, "r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                records.append(dict(row))
    return records


def clear_attack_logs():
    """Clear all attack log entries (keeps header)."""
    with _log_lock:
        with open(ATTACK_LOG_PATH, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=LOG_COLUMNS)
            writer.writeheader()
    system_logger.info("Attack logs cleared.")


# ─── Convenience wrappers ─────────────────────────────────────────────────────
def info(msg: str, *args):
    system_logger.info(msg, *args)


def warning(msg: str, *args):
    system_logger.warning(msg, *args)


def error(msg: str, *args):
    system_logger.error(msg, *args)


def debug(msg: str, *args):
    system_logger.debug(msg, *args)
