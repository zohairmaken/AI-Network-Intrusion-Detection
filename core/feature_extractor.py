# =============================================================================
# core/feature_extractor.py
# Converts raw Scapy packets into ML-ready feature vectors
# =============================================================================

import time
import numpy as np
from collections import defaultdict
from typing import Optional, Dict, Any

from config.constants import (
    PROTO_TCP, PROTO_UDP, PROTO_ICMP,
    TCP_FLAG_SYN, TCP_FLAG_ACK, TCP_FLAG_FIN,
    TCP_FLAG_RST, TCP_FLAG_PSH, TCP_FLAG_URG,
    SENSITIVE_PORTS, FEATURE_COLUMNS
)

# ─── Flow tracker for inter-arrival time & packet rate ───────────────────────
_flow_tracker: Dict[str, Dict] = defaultdict(lambda: {
    "pkt_count": 0,
    "byte_count": 0,
    "last_seen": time.time(),
    "first_seen": time.time(),
    "timestamps": []
})

_port_scan_tracker: Dict[str, set] = defaultdict(set)  # src_ip -> set of dst_ports


def _flow_key(src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: int) -> str:
    return f"{src_ip}:{src_port}->{dst_ip}:{dst_port}|{proto}"


def _update_flow(key: str, pkt_len: int) -> Dict:
    """Update per-flow statistics and return current flow stats."""
    now = time.time()
    flow = _flow_tracker[key]
    flow["pkt_count"] += 1
    flow["byte_count"] += pkt_len
    flow["timestamps"].append(now)
    # Keep only last 100 timestamps
    if len(flow["timestamps"]) > 100:
        flow["timestamps"] = flow["timestamps"][-100:]
    duration = now - flow["first_seen"]
    flow_rate = flow["pkt_count"] / max(duration, 0.001)
    inter_arrival = 0.0
    if len(flow["timestamps"]) >= 2:
        diffs = [flow["timestamps"][i] - flow["timestamps"][i-1]
                 for i in range(1, len(flow["timestamps"]))]
        inter_arrival = float(np.mean(diffs))
    flow["last_seen"] = now
    return {
        "duration": round(duration, 4),
        "pkt_count": flow["pkt_count"],
        "byte_count": flow["byte_count"],
        "flow_rate": round(flow_rate, 4),
        "inter_arrival_time": round(inter_arrival, 6)
    }


def _port_scan_score(src_ip: str, dst_port: int) -> float:
    """
    Heuristic: score 0-1 based on how many unique ports this src_ip has probed.
    High score = likely port scanner.
    """
    _port_scan_tracker[src_ip].add(dst_port)
    unique_ports = len(_port_scan_tracker[src_ip])
    # Normalize: >30 unique ports within session = max score
    return min(unique_ports / 30.0, 1.0)


def _dos_score(flow_rate: float, inter_arrival: float) -> float:
    """
    Heuristic: very high packet rate + very low inter-arrival = DoS-like.
    Returns score 0-1.
    """
    rate_score = min(flow_rate / 1000.0, 1.0)   # 1000 pkt/s = max
    iat_score  = max(0, 1.0 - inter_arrival * 100)  # <10ms IAT = suspicious
    return round((rate_score + iat_score) / 2.0, 4)


def extract_features(packet) -> Optional[Dict[str, Any]]:
    """
    Extract ML features from a Scapy packet.

    Args:
        packet: Scapy packet object

    Returns:
        Dictionary of features matching FEATURE_COLUMNS, or None if not extractable.
    """
    try:
        # Requires IP layer
        if not packet.haslayer("IP"):
            return None

        ip = packet["IP"]
        src_ip  = ip.src
        dst_ip  = ip.dst
        proto   = ip.proto
        pkt_len = len(packet)

        # ── Port & flag extraction ──────────────────────────────────────────
        src_port = 0
        dst_port = 0
        flag_syn = flag_ack = flag_fin = flag_rst = flag_psh = flag_urg = 0

        if proto == PROTO_TCP and packet.haslayer("TCP"):
            tcp = packet["TCP"]
            src_port = int(tcp.sport)
            dst_port = int(tcp.dport)
            flags     = int(tcp.flags)
            flag_syn  = int(bool(flags & TCP_FLAG_SYN))
            flag_ack  = int(bool(flags & TCP_FLAG_ACK))
            flag_fin  = int(bool(flags & TCP_FLAG_FIN))
            flag_rst  = int(bool(flags & TCP_FLAG_RST))
            flag_psh  = int(bool(flags & TCP_FLAG_PSH))
            flag_urg  = int(bool(flags & TCP_FLAG_URG))

        elif proto == PROTO_UDP and packet.haslayer("UDP"):
            udp = packet["UDP"]
            src_port = int(udp.sport)
            dst_port = int(udp.dport)

        # ── Flow statistics ────────────────────────────────────────────────
        key   = _flow_key(src_ip, dst_ip, src_port, dst_port, proto)
        stats = _update_flow(key, pkt_len)

        # ── Derived heuristic scores ───────────────────────────────────────
        ps_score  = _port_scan_score(src_ip, dst_port)
        dos_score = _dos_score(stats["flow_rate"], stats["inter_arrival_time"])
        is_sens   = int(dst_port in SENSITIVE_PORTS or src_port in SENSITIVE_PORTS)

        features = {
            "duration":           stats["duration"],
            "protocol_type":      int(proto),
            "src_port":           src_port,
            "dst_port":           dst_port,
            "pkt_length":         pkt_len,
            "flag_syn":           flag_syn,
            "flag_ack":           flag_ack,
            "flag_fin":           flag_fin,
            "flag_rst":           flag_rst,
            "flag_psh":           flag_psh,
            "flag_urg":           flag_urg,
            "pkt_count":          stats["pkt_count"],
            "byte_count":         stats["byte_count"],
            "flow_rate":          stats["flow_rate"],
            "inter_arrival_time": stats["inter_arrival_time"],
            "is_sensitive_port":  is_sens,
            "port_scan_score":    ps_score,
            "dos_score":          dos_score,
            # Metadata (not fed to model)
            "_src_ip":   src_ip,
            "_dst_ip":   dst_ip,
            "_protocol": proto
        }
        return features

    except Exception:
        return None


def features_to_vector(features: Dict[str, Any]) -> np.ndarray:
    """
    Convert a features dict to a numpy array in the correct column order.

    Args:
        features: Dict from extract_features()

    Returns:
        1-D numpy array of shape (len(FEATURE_COLUMNS),)
    """
    return np.array([features.get(col, 0.0) for col in FEATURE_COLUMNS], dtype=np.float64)


def reset_flow_tracker():
    """Clear in-memory flow and port-scan trackers (call between sessions)."""
    _flow_tracker.clear()
    _port_scan_tracker.clear()
