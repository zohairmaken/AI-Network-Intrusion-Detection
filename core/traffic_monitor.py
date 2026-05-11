# =============================================================================
# core/traffic_monitor.py
# Orchestrates live packet sniffing → feature extraction → ML prediction
# =============================================================================

import threading
import time
import pandas as pd
from collections import deque
from typing import Callable, Optional, List, Dict

from core.packet_sniffer import (
    start_sniffer, stop_sniffer, get_packet,
    is_running as sniffer_running, get_stats as sniffer_stats
)
from core.feature_extractor import extract_features, reset_flow_tracker
from core.intrusion_detector import predict, is_initialized
import core.logger as log
from config.config import DASHBOARD_REFRESH_INTERVAL, LIVE_GRAPH_POINTS
from config.constants import CLASS_NORMAL

# ─── Shared live data structures (thread-safe deques) ─────────────────────────
MAX_LIVE_EVENTS = 200
live_alerts: deque  = deque(maxlen=MAX_LIVE_EVENTS)   # recent threat dicts
live_packets: deque = deque(maxlen=MAX_LIVE_EVENTS)   # recent packet dicts

# ─── Traffic statistics ────────────────────────────────────────────────────────
_stats_lock = threading.Lock()
_traffic_stats = {
    "total_packets":    0,
    "attack_packets":   0,
    "normal_packets":   0,
    "dos_count":        0,
    "port_scan_count":  0,
    "brute_force_count":0,
    "suspicious_count": 0,
    "bytes_total":      0,
    "packets_per_sec":  0.0,
    "running":          False,
    "start_time":       None,
    "model_used":       "random_forest"
}

# Time-series for live graph
_packet_timeline: deque = deque(maxlen=LIVE_GRAPH_POINTS)
_attack_timeline: deque = deque(maxlen=LIVE_GRAPH_POINTS)
_time_labels:     deque = deque(maxlen=LIVE_GRAPH_POINTS)

# ─── Worker thread ────────────────────────────────────────────────────────────
_worker_thread: Optional[threading.Thread] = None
_stop_worker = threading.Event()

# ─── Event callbacks ──────────────────────────────────────────────────────────
_on_alert: Optional[Callable] = None   # called on each attack detection
_on_packet: Optional[Callable] = None  # called on each processed packet


def _process_loop(model_name: str, demo_mode: bool, demo_rows: list):
    """
    Main worker: pull packets from sniffer queue (or demo rows),
    extract features, predict, and update stats.
    """
    global _traffic_stats

    packet_src = iter(demo_rows) if demo_mode else None
    last_stat_time = time.time()
    packets_since_last = 0

    while not _stop_worker.is_set():
        # ── Get next packet ────────────────────────────────────────────────
        if demo_mode:
            try:
                raw = next(packet_src)
            except StopIteration:
                # Loop demo data
                packet_src = iter(demo_rows)
                raw = next(packet_src)
            time.sleep(0.05)  # simulate capture delay
            features = _demo_row_to_features(raw)
        else:
            raw = get_packet(timeout=1.0)
            if raw is None:
                continue
            features = extract_features(raw)

        if features is None:
            continue

        # ── Predict ────────────────────────────────────────────────────────
        result = predict(features, model_name=model_name)
        if result is None:
            continue

        # ── Update stats ───────────────────────────────────────────────────
        with _stats_lock:
            _traffic_stats["total_packets"]  += 1
            _traffic_stats["bytes_total"]    += features.get("pkt_length", 0)
            packets_since_last               += 1

            pred = result["prediction"]
            if pred == CLASS_NORMAL:
                _traffic_stats["normal_packets"] += 1
            else:
                _traffic_stats["attack_packets"] += 1
                _update_attack_type_counter(pred)

            # Update packets-per-second every second
            now = time.time()
            if now - last_stat_time >= 1.0:
                _traffic_stats["packets_per_sec"] = round(
                    packets_since_last / (now - last_stat_time), 1
                )
                packets_since_last = 0
                last_stat_time = now
                # Push to timeline
                _packet_timeline.append(_traffic_stats["total_packets"])
                _attack_timeline.append(_traffic_stats["attack_packets"])
                _time_labels.append(time.strftime("%H:%M:%S"))

        # ── Append to live feeds ───────────────────────────────────────────
        pkt_summary = {
            "time":       time.strftime("%H:%M:%S"),
            "src_ip":     result["src_ip"],
            "dst_ip":     result["dst_ip"],
            "protocol":   features.get("protocol_type", 0),
            "length":     features.get("pkt_length", 0),
            "prediction": pred,
            "severity":   result["severity"],
            "confidence": round(result["confidence"] * 100, 1)
        }
        live_packets.append(pkt_summary)

        if pred != CLASS_NORMAL:
            live_alerts.append(result)
            if _on_alert:
                _on_alert(result)

        if _on_packet:
            _on_packet(pkt_summary)

    log.info("Traffic monitor worker stopped.")


def _update_attack_type_counter(pred: str):
    """Update per-type counters (must be called inside _stats_lock)."""
    from config.constants import CLASS_DOS, CLASS_PORT_SCAN, CLASS_BRUTE_FORCE, CLASS_SUSPICIOUS
    if pred == CLASS_DOS:
        _traffic_stats["dos_count"] += 1
    elif pred == CLASS_PORT_SCAN:
        _traffic_stats["port_scan_count"] += 1
    elif pred == CLASS_BRUTE_FORCE:
        _traffic_stats["brute_force_count"] += 1
    elif pred == CLASS_SUSPICIOUS:
        _traffic_stats["suspicious_count"] += 1


def _demo_row_to_features(row: dict) -> dict:
    """Convert a demo CSV row dict to a features dict."""
    from config.constants import FEATURE_COLUMNS
    features = {col: float(row.get(col, 0)) for col in FEATURE_COLUMNS}
    features["_src_ip"]   = str(row.get("src_ip", "192.168.1.100"))
    features["_dst_ip"]   = str(row.get("dst_ip", "10.0.0.1"))
    features["_protocol"] = str(row.get("protocol_type", 6))
    return features


def start_monitoring(
    interface: Optional[str] = None,
    model_name: str = "random_forest",
    bpf_filter: str = "ip",
    demo_mode: bool = False,
    demo_rows: Optional[List[dict]] = None,
    on_alert: Optional[Callable] = None,
    on_packet: Optional[Callable] = None
):
    """
    Start traffic monitoring.

    Args:
        interface  : Network interface (None = auto)
        model_name : ML model to use
        bpf_filter : Scapy BPF filter
        demo_mode  : If True, replay demo_rows instead of live capture
        demo_rows  : List of dicts for demo mode
        on_alert   : Callback for each detected attack
        on_packet  : Callback for each processed packet
    """
    global _worker_thread, _on_alert, _on_packet, _traffic_stats

    if _traffic_stats["running"]:
        log.warning("Monitoring already running.")
        return

    _on_alert  = on_alert
    _on_packet = on_packet
    _stop_worker.clear()

    # Reset stats
    with _stats_lock:
        _traffic_stats.update({
            "total_packets": 0, "attack_packets": 0, "normal_packets": 0,
            "dos_count": 0, "port_scan_count": 0,
            "brute_force_count": 0, "suspicious_count": 0,
            "bytes_total": 0, "packets_per_sec": 0.0,
            "running": True, "start_time": time.time(),
            "model_used": model_name
        })
    live_alerts.clear()
    live_packets.clear()
    _packet_timeline.clear()
    _attack_timeline.clear()
    _time_labels.clear()
    reset_flow_tracker()

    if not demo_mode:
        start_sniffer(interface=interface, bpf_filter=bpf_filter)

    _worker_thread = threading.Thread(
        target=_process_loop,
        args=(model_name, demo_mode, demo_rows or []),
        daemon=True,
        name="TrafficMonitor"
    )
    _worker_thread.start()
    log.info("Traffic monitoring started | demo=%s | model=%s", demo_mode, model_name)


def stop_monitoring():
    """Stop traffic monitoring and sniffer."""
    global _traffic_stats
    _stop_worker.set()
    if not _traffic_stats.get("demo_mode", False):
        stop_sniffer()
    with _stats_lock:
        _traffic_stats["running"] = False
    log.info("Traffic monitoring stopped.")


def get_traffic_stats() -> dict:
    with _stats_lock:
        return dict(_traffic_stats)


def get_timeline_data() -> dict:
    """Return time-series data for dashboard charts."""
    return {
        "labels":  list(_time_labels),
        "packets": list(_packet_timeline),
        "attacks": list(_attack_timeline)
    }


def get_recent_alerts(n: int = 20) -> list:
    alerts = list(live_alerts)
    return alerts[-n:] if len(alerts) > n else alerts


def get_recent_packets(n: int = 50) -> list:
    pkts = list(live_packets)
    return pkts[-n:] if len(pkts) > n else pkts


def is_monitoring() -> bool:
    return _traffic_stats.get("running", False)
