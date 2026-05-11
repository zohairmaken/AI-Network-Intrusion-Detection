# =============================================================================
# tests/test_dashboard.py
# Unit tests for alert system, threat analyzer, and utility functions
# =============================================================================

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from app.alert_system import create_alert, add_alert, get_alerts, clear_alerts
from core.threat_analyzer import calculate_severity, get_risk_score, analyze_threat
from app.utils import format_bytes, format_duration, protocol_name
from config.constants import (
    CLASS_DOS, CLASS_NORMAL, CLASS_PORT_SCAN, CLASS_BRUTE_FORCE,
    SEVERITY_HIGH, SEVERITY_CRITICAL, SEVERITY_LOW, SEVERITY_MEDIUM
)


class TestAlertSystem(unittest.TestCase):

    def setUp(self):
        clear_alerts()

    def test_create_alert_normal_returns_none(self):
        result = create_alert({"prediction": CLASS_NORMAL, "severity": SEVERITY_LOW,
                               "confidence": 0.99, "risk_score": 0.0,
                               "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2",
                               "dst_port": 80, "action": "Allow", "flow_rate": 10.0})
        self.assertIsNone(result)

    def test_create_alert_attack(self):
        result = create_alert({"prediction": CLASS_DOS, "severity": SEVERITY_HIGH,
                               "confidence": 0.92, "risk_score": 0.7,
                               "src_ip": "10.0.0.1", "dst_ip": "192.168.1.1",
                               "dst_port": 80, "action": "BLOCK", "flow_rate": 500.0})
        self.assertIsNotNone(result)
        self.assertEqual(result["prediction"], CLASS_DOS)
        self.assertEqual(result["severity"], SEVERITY_HIGH)

    def test_alerts_stored_after_add(self):
        threat = {"prediction": CLASS_PORT_SCAN, "severity": SEVERITY_MEDIUM,
                  "confidence": 0.78, "risk_score": 0.4, "src_ip": "10.0.0.2",
                  "dst_ip": "192.168.1.1", "dst_port": 443, "action": "LOG", "flow_rate": 20.0}
        add_alert(threat)
        alerts = get_alerts()
        self.assertEqual(len(alerts), 1)

    def test_clear_alerts(self):
        threat = {"prediction": CLASS_BRUTE_FORCE, "severity": SEVERITY_CRITICAL,
                  "confidence": 0.95, "risk_score": 0.9, "src_ip": "10.0.0.3",
                  "dst_ip": "192.168.1.5", "dst_port": 22, "action": "BLOCK", "flow_rate": 30.0}
        add_alert(threat)
        clear_alerts()
        alerts = get_alerts()
        self.assertEqual(len(alerts), 0)


class TestThreatAnalyzer(unittest.TestCase):

    def test_normal_is_low_severity(self):
        sev = calculate_severity(CLASS_NORMAL, 0.99)
        self.assertEqual(sev, SEVERITY_LOW)

    def test_dos_high_confidence_is_high(self):
        sev = calculate_severity(CLASS_DOS, 0.95, dst_port=80)
        self.assertIn(sev, [SEVERITY_HIGH, SEVERITY_CRITICAL])

    def test_risk_score_normal_is_zero(self):
        score = get_risk_score(CLASS_NORMAL, 0.99, SEVERITY_LOW)
        self.assertEqual(score, 0.0)

    def test_risk_score_critical_high(self):
        score = get_risk_score(CLASS_DOS, 0.95, SEVERITY_CRITICAL)
        self.assertGreater(score, 0.5)

    def test_analyze_threat_returns_dict(self):
        features = {col: 0.0 for col in ["dst_port","flow_rate","dos_score",
                                          "port_scan_score","_src_ip","_dst_ip",
                                          "pkt_length","protocol_type"]}
        features["_src_ip"] = "10.0.0.1"
        features["_dst_ip"] = "192.168.1.1"
        result = analyze_threat(CLASS_DOS, 0.9, features)
        self.assertIn("severity", result)
        self.assertIn("risk_score", result)
        self.assertIn("action", result)
        self.assertTrue(result["is_attack"])


class TestUtils(unittest.TestCase):

    def test_format_bytes_kb(self):
        self.assertEqual(format_bytes(1024), "1.0 KB")

    def test_format_bytes_mb(self):
        self.assertEqual(format_bytes(1024 * 1024), "1.0 MB")

    def test_format_duration_seconds(self):
        result = format_duration(45)
        self.assertIn("45s", result)

    def test_format_duration_minutes(self):
        result = format_duration(90)
        self.assertIn("m", result)

    def test_protocol_name_tcp(self):
        self.assertEqual(protocol_name(6), "TCP")

    def test_protocol_name_udp(self):
        self.assertEqual(protocol_name(17), "UDP")

    def test_protocol_name_icmp(self):
        self.assertEqual(protocol_name(1), "ICMP")

    def test_protocol_name_unknown(self):
        result = protocol_name(999)
        self.assertIn("999", result)


if __name__ == "__main__":
    unittest.main()
