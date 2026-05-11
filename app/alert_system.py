# =============================================================================
# app/alert_system.py
# Alert generation, notification handling, and email alerting
# =============================================================================

import smtplib
import threading
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from collections import deque
from typing import Optional, Callable

from config.config import (
    EMAIL_ALERTS_ENABLED, SMTP_SERVER, SMTP_PORT,
    SENDER_EMAIL, RECEIVER_EMAIL, EMAIL_APP_PASSWORD,
    ALERT_THRESHOLD_HIGH, ALERT_THRESHOLD_MEDIUM,
    MAX_ALERTS_DISPLAY
)
from config.constants import (
    SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW,
    CLASS_NORMAL
)
from config.config import SEVERITY_COLORS
import core.logger as log

# ─── In-memory alert store ────────────────────────────────────────────────────
_alert_queue: deque = deque(maxlen=MAX_ALERTS_DISPLAY)
_alert_lock = threading.Lock()

# ─── Alert counters ────────────────────────────────────────────────────────────
_alert_stats = {
    "total":    0,
    "critical": 0,
    "high":     0,
    "medium":   0,
    "low":      0,
    "email_sent": 0
}


def create_alert(threat_result: dict) -> Optional[dict]:
    """
    Build an alert dict from a threat analysis result.

    Args:
        threat_result: Output from threat_analyzer.analyze_threat()

    Returns:
        Alert dict, or None if prediction is NORMAL
    """
    if threat_result.get("prediction") == CLASS_NORMAL:
        return None

    alert = {
        "id":          _alert_stats["total"] + 1,
        "timestamp":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "prediction":  threat_result["prediction"],
        "severity":    threat_result["severity"],
        "confidence":  threat_result["confidence"],
        "risk_score":  threat_result["risk_score"],
        "src_ip":      threat_result.get("src_ip", "N/A"),
        "dst_ip":      threat_result.get("dst_ip", "N/A"),
        "dst_port":    threat_result.get("dst_port", 0),
        "action":      threat_result.get("action", "LOG"),
        "flow_rate":   threat_result.get("flow_rate", 0.0),
        "acknowledged": False,
        "color":       SEVERITY_COLORS.get(threat_result["prediction"], "#ffffff")
    }
    return alert


def add_alert(threat_result: dict, on_critical: Optional[Callable] = None) -> Optional[dict]:
    """
    Process a threat result into an alert, store it, and trigger notifications.

    Args:
        threat_result : Dict from threat_analyzer.analyze_threat()
        on_critical   : Optional callback for CRITICAL alerts

    Returns:
        Created alert dict or None
    """
    alert = create_alert(threat_result)
    if alert is None:
        return None

    with _alert_lock:
        _alert_queue.appendleft(alert)
        _alert_stats["total"] += 1
        sev = alert["severity"].lower()
        if sev in _alert_stats:
            _alert_stats[sev] += 1

    log.info(
        "ALERT #%d | %s [%s] | %s → %s | Conf: %.1f%%",
        alert["id"], alert["prediction"], alert["severity"],
        alert["src_ip"], alert["dst_ip"], alert["confidence"] * 100
    )

    # Email for HIGH/CRITICAL
    if alert["severity"] in (SEVERITY_CRITICAL, SEVERITY_HIGH):
        if EMAIL_ALERTS_ENABLED:
            threading.Thread(
                target=_send_email_alert,
                args=(alert,),
                daemon=True
            ).start()
        if on_critical and alert["severity"] == SEVERITY_CRITICAL:
            on_critical(alert)

    return alert


def get_alerts(n: int = MAX_ALERTS_DISPLAY, severity_filter: str = None) -> list:
    """
    Retrieve recent alerts.

    Args:
        n              : Max number of alerts to return
        severity_filter: If set, return only alerts of this severity level

    Returns:
        List of alert dicts (newest first)
    """
    with _alert_lock:
        alerts = list(_alert_queue)

    if severity_filter:
        alerts = [a for a in alerts if a["severity"] == severity_filter]

    return alerts[:n]


def get_alert_stats() -> dict:
    """Return current alert counters."""
    with _alert_lock:
        return dict(_alert_stats)


def acknowledge_alert(alert_id: int) -> bool:
    """Mark an alert as acknowledged by ID."""
    with _alert_lock:
        for alert in _alert_queue:
            if alert["id"] == alert_id:
                alert["acknowledged"] = True
                return True
    return False


def clear_alerts():
    """Clear all alerts from memory."""
    with _alert_lock:
        _alert_queue.clear()
        for key in _alert_stats:
            _alert_stats[key] = 0
    log.info("Alert queue cleared.")


def _send_email_alert(alert: dict):
    """
    Send an email notification for a HIGH/CRITICAL alert.
    Runs in a background thread to avoid blocking the UI.
    """
    if not EMAIL_APP_PASSWORD:
        log.warning("Email alerting enabled but EMAIL_APP_PASSWORD is not set.")
        return

    try:
        subject = f"[NIDS ALERT] {alert['severity']} — {alert['prediction']} Detected"
        body = f"""
        <html><body style="font-family: Arial, sans-serif; background:#0a0e1a; color:#e2e8f0; padding:20px;">
        <div style="border: 2px solid #ff4444; border-radius:8px; padding:20px; max-width:600px;">
            <h2 style="color:#ff4444;">🚨 NIDS Security Alert</h2>
            <table style="width:100%; border-collapse:collapse;">
                <tr><td style="padding:8px; color:#94a3b8;">Timestamp</td>
                    <td style="padding:8px; font-weight:bold;">{alert['timestamp']}</td></tr>
                <tr><td style="padding:8px; color:#94a3b8;">Attack Type</td>
                    <td style="padding:8px; font-weight:bold; color:#ff4444;">{alert['prediction']}</td></tr>
                <tr><td style="padding:8px; color:#94a3b8;">Severity</td>
                    <td style="padding:8px; font-weight:bold;">{alert['severity']}</td></tr>
                <tr><td style="padding:8px; color:#94a3b8;">Confidence</td>
                    <td style="padding:8px;">{alert['confidence']*100:.1f}%</td></tr>
                <tr><td style="padding:8px; color:#94a3b8;">Source IP</td>
                    <td style="padding:8px;">{alert['src_ip']}</td></tr>
                <tr><td style="padding:8px; color:#94a3b8;">Destination</td>
                    <td style="padding:8px;">{alert['dst_ip']}:{alert['dst_port']}</td></tr>
                <tr><td style="padding:8px; color:#94a3b8;">Action</td>
                    <td style="padding:8px; color:#ffdd00;">{alert['action']}</td></tr>
            </table>
            <p style="margin-top:16px; color:#64748b; font-size:12px;">
                This alert was generated automatically by the AI-NIDS system.
            </p>
        </div>
        </body></html>
        """

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = SENDER_EMAIL
        msg["To"]      = RECEIVER_EMAIL
        msg.attach(MIMEText(body, "html"))

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SENDER_EMAIL, EMAIL_APP_PASSWORD)
            server.send_message(msg)

        _alert_stats["email_sent"] += 1
        log.info("Email alert sent for alert #%d", alert["id"])

    except Exception as e:
        log.error("Failed to send email alert: %s", str(e))


def format_alert_for_display(alert: dict) -> str:
    """Return a single-line summary string for an alert."""
    return (
        f"[{alert['timestamp']}] {alert['severity']} | "
        f"{alert['prediction']} | "
        f"{alert['src_ip']} → {alert['dst_ip']}:{alert['dst_port']} | "
        f"Conf: {alert['confidence']*100:.0f}%"
    )
