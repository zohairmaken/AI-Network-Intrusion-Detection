# =============================================================================
# core/packet_sniffer.py
# Real-time packet capturing using Scapy with thread-safe queue
# =============================================================================

import threading
import queue
import time
from typing import Callable, Optional

from config.config import (
    SNIFF_INTERFACE, MAX_PACKETS_PER_SESSION,
    PACKET_CAPTURE_TIMEOUT, PROMISCUOUS_MODE
)
import core.logger as log

# ─── Shared packet queue ──────────────────────────────────────────────────────
packet_queue: queue.Queue = queue.Queue(maxsize=5000)

# ─── Sniffer state ────────────────────────────────────────────────────────────
_sniffer_thread: Optional[threading.Thread] = None
_stop_event = threading.Event()
_stats = {
    "total_captured": 0,
    "total_dropped":  0,
    "running":        False,
    "start_time":     None,
    "interface":      None
}


def _packet_handler(pkt):
    """Callback invoked by Scapy for each captured packet."""
    global _stats
    if _stop_event.is_set():
        return True  # signal Scapy to stop
    try:
        packet_queue.put_nowait(pkt)
        _stats["total_captured"] += 1
    except queue.Full:
        _stats["total_dropped"] += 1


def _sniff_loop(interface: Optional[str], bpf_filter: str, count: int):
    """
    Run Scapy sniff in a background thread.
    Automatically stops when _stop_event is set.
    """
    from scapy.all import sniff
    log.info("Packet sniffer started | interface=%s | filter='%s'", interface, bpf_filter)
    try:
        sniff(
            iface=interface,
            prn=_packet_handler,
            filter=bpf_filter,
            count=count,
            store=False,
            stop_filter=lambda _: _stop_event.is_set(),
            promisc=PROMISCUOUS_MODE
        )
    except Exception as e:
        log.error("Sniffer error: %s", str(e))
    finally:
        _stats["running"] = False
        log.info(
            "Packet sniffer stopped | captured=%d | dropped=%d",
            _stats["total_captured"], _stats["total_dropped"]
        )


def start_sniffer(
    interface: Optional[str] = None,
    bpf_filter: str = "ip",
    count: int = 0,
    on_start: Optional[Callable] = None
):
    """
    Start the packet sniffer in a background daemon thread.

    Args:
        interface : Network interface name (None = Scapy default)
        bpf_filter: BPF filter string (e.g. 'tcp', 'udp', 'ip')
        count     : Number of packets to capture (0 = unlimited)
        on_start  : Optional callback invoked when sniffing begins
    """
    global _sniffer_thread, _stats

    if _stats["running"]:
        log.warning("Sniffer already running.")
        return

    _stop_event.clear()
    iface = interface or SNIFF_INTERFACE

    _stats.update({
        "total_captured": 0,
        "total_dropped":  0,
        "running":        True,
        "start_time":     time.time(),
        "interface":      iface or "default"
    })

    # Clear any stale packets from previous session
    while not packet_queue.empty():
        try:
            packet_queue.get_nowait()
        except queue.Empty:
            break

    _sniffer_thread = threading.Thread(
        target=_sniff_loop,
        args=(iface, bpf_filter, count),
        daemon=True,
        name="PacketSniffer"
    )
    _sniffer_thread.start()

    if on_start:
        on_start()

    log.info("Sniffer thread launched (daemon=True).")


def stop_sniffer():
    """Signal the sniffer to stop and wait for thread to finish."""
    global _stats
    if not _stats["running"]:
        return
    log.info("Stopping packet sniffer...")
    _stop_event.set()
    if _sniffer_thread and _sniffer_thread.is_alive():
        _sniffer_thread.join(timeout=5)
    _stats["running"] = False


def is_running() -> bool:
    return _stats["running"]


def get_stats() -> dict:
    """Return current sniffer statistics."""
    stats = dict(_stats)
    if stats["start_time"]:
        stats["uptime_seconds"] = round(time.time() - stats["start_time"], 1)
    else:
        stats["uptime_seconds"] = 0
    stats["queue_size"] = packet_queue.qsize()
    return stats


def get_packet(timeout: float = 1.0):
    """
    Retrieve one packet from the queue (blocking with timeout).

    Returns:
        Scapy packet or None if queue is empty.
    """
    try:
        return packet_queue.get(timeout=timeout)
    except queue.Empty:
        return None


def simulate_packet_from_row(row: dict):
    """
    For demo/testing: inject a mock packet-like object into the queue
    from a CSV row (used when real sniffing isn't available).
    """
    packet_queue.put_nowait(row)
    _stats["total_captured"] += 1
