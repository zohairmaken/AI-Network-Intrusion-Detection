# =============================================================================
# core/threat_analyzer.py
# Threat severity scoring and risk assessment engine
# =============================================================================

from config.constants import (
    CLASS_NORMAL, CLASS_DOS, CLASS_PORT_SCAN,
    CLASS_BRUTE_FORCE, CLASS_SUSPICIOUS,
    SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL,
    SEVERITY_SCORE, SENSITIVE_PORTS
)
from config.config import ALERT_THRESHOLD_HIGH, ALERT_THRESHOLD_MEDIUM


# ─── Base severity mapping per attack type ────────────────────────────────────
_BASE_SEVERITY = {
    CLASS_NORMAL:       None,           # No severity for normal
    CLASS_DOS:          SEVERITY_HIGH,
    CLASS_PORT_SCAN:    SEVERITY_MEDIUM,
    CLASS_BRUTE_FORCE:  SEVERITY_CRITICAL,
    CLASS_SUSPICIOUS:   SEVERITY_LOW
}


def calculate_severity(
    prediction: str,
    confidence: float,
    dst_port: int = 0,
    src_ip: str = "",
    is_blacklisted: bool = False,
    flow_rate: float = 0.0,
    dos_score: float = 0.0,
    port_scan_score: float = 0.0
) -> str:
    """
    Calculate final severity level for a detected threat.

    Factors considered:
      - Base severity for attack type
      - Confidence score
      - Target port sensitivity
      - Blacklist status
      - Flow rate (for DoS)
      - Heuristic scores

    Returns:
        One of: SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL
    """
    if prediction == CLASS_NORMAL:
        return SEVERITY_LOW

    base = _BASE_SEVERITY.get(prediction, SEVERITY_MEDIUM)
    score = SEVERITY_SCORE[base]

    # ── Confidence modifier ────────────────────────────────────────────────────
    if confidence >= ALERT_THRESHOLD_HIGH:
        score += 1
    elif confidence < ALERT_THRESHOLD_MEDIUM:
        score -= 1

    # ── Sensitive port modifier ────────────────────────────────────────────────
    if dst_port in SENSITIVE_PORTS:
        score += 1

    # ── Blacklist modifier ─────────────────────────────────────────────────────
    if is_blacklisted:
        score += 1

    # ── DoS rate modifier ─────────────────────────────────────────────────────
    if prediction == CLASS_DOS and flow_rate > 500:
        score += 1

    # ── Clamp to valid range ───────────────────────────────────────────────────
    score = max(1, min(score, 4))

    return {
        1: SEVERITY_LOW,
        2: SEVERITY_MEDIUM,
        3: SEVERITY_HIGH,
        4: SEVERITY_CRITICAL
    }[score]


def get_risk_score(prediction: str, confidence: float, severity: str) -> float:
    """
    Return a normalized risk score 0.0-1.0 for dashboard display.

    Combines severity level and model confidence.
    """
    if prediction == CLASS_NORMAL:
        return 0.0
    sev_weight = {
        SEVERITY_LOW:      0.25,
        SEVERITY_MEDIUM:   0.50,
        SEVERITY_HIGH:     0.75,
        SEVERITY_CRITICAL: 1.00
    }.get(severity, 0.25)
    return round(sev_weight * confidence, 4)


def get_recommended_action(prediction: str, severity: str, is_blacklisted: bool) -> str:
    """
    Return a recommended action string based on threat type and severity.
    """
    if prediction == CLASS_NORMAL:
        return "Allow"

    if is_blacklisted:
        return "BLOCK — Source IP blacklisted"

    actions = {
        (CLASS_DOS,          SEVERITY_CRITICAL): "BLOCK — Rate-limit & alert SOC",
        (CLASS_DOS,          SEVERITY_HIGH):     "BLOCK — Implement rate limiting",
        (CLASS_DOS,          SEVERITY_MEDIUM):   "ALERT — Monitor traffic volume",
        (CLASS_BRUTE_FORCE,  SEVERITY_CRITICAL): "BLOCK — Lock account & alert admin",
        (CLASS_BRUTE_FORCE,  SEVERITY_HIGH):     "BLOCK — Temporary IP block",
        (CLASS_BRUTE_FORCE,  SEVERITY_MEDIUM):   "ALERT — Monitor auth attempts",
        (CLASS_PORT_SCAN,    SEVERITY_HIGH):     "ALERT — Investigate source IP",
        (CLASS_PORT_SCAN,    SEVERITY_MEDIUM):   "LOG — Track scanning activity",
        (CLASS_SUSPICIOUS,   SEVERITY_HIGH):     "ALERT — Deep packet inspection",
        (CLASS_SUSPICIOUS,   SEVERITY_MEDIUM):   "LOG — Monitor for escalation",
    }
    return actions.get((prediction, severity), "LOG — Monitor")


def analyze_threat(
    prediction: str,
    confidence: float,
    features: dict,
    is_blacklisted: bool = False
) -> dict:
    """
    Full threat analysis pipeline.

    Args:
        prediction    : Predicted class label
        confidence    : Model confidence score (0-1)
        features      : Feature dict from feature_extractor
        is_blacklisted: Whether src_ip is on blacklist

    Returns:
        Dict with severity, risk_score, action, and summary
    """
    dst_port       = features.get("dst_port", 0)
    flow_rate      = features.get("flow_rate", 0.0)
    dos_score      = features.get("dos_score", 0.0)
    port_scan_score = features.get("port_scan_score", 0.0)
    src_ip         = features.get("_src_ip", "")

    severity = calculate_severity(
        prediction=prediction,
        confidence=confidence,
        dst_port=dst_port,
        src_ip=src_ip,
        is_blacklisted=is_blacklisted,
        flow_rate=flow_rate,
        dos_score=dos_score,
        port_scan_score=port_scan_score
    )
    risk_score = get_risk_score(prediction, confidence, severity)
    action     = get_recommended_action(prediction, severity, is_blacklisted)

    return {
        "prediction":    prediction,
        "confidence":    confidence,
        "severity":      severity,
        "risk_score":    risk_score,
        "action":        action,
        "src_ip":        src_ip,
        "dst_ip":        features.get("_dst_ip", ""),
        "dst_port":      dst_port,
        "protocol":      features.get("protocol_type", 0),
        "pkt_length":    features.get("pkt_length", 0),
        "flow_rate":     flow_rate,
        "is_attack":     prediction != CLASS_NORMAL
    }
