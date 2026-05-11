# =============================================================================
# tests/test_feature_extraction.py
# Unit tests for feature extraction engine
# =============================================================================

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
import numpy as np
from unittest.mock import MagicMock, patch
from core.feature_extractor import (
    extract_features, features_to_vector, reset_flow_tracker,
    _port_scan_score, _dos_score
)
from config.constants import FEATURE_COLUMNS


class TestFeatureExtractor(unittest.TestCase):

    def setUp(self):
        reset_flow_tracker()

    def test_features_to_vector_shape(self):
        features = {col: 0.0 for col in FEATURE_COLUMNS}
        vec = features_to_vector(features)
        self.assertEqual(vec.shape, (len(FEATURE_COLUMNS),))
        self.assertEqual(vec.dtype, np.float64)

    def test_features_to_vector_values(self):
        features = {col: float(i) for i, col in enumerate(FEATURE_COLUMNS)}
        vec = features_to_vector(features)
        self.assertEqual(vec[0], 0.0)
        self.assertEqual(vec[1], 1.0)

    def test_port_scan_score_increases(self):
        reset_flow_tracker()
        scores = [_port_scan_score("10.0.0.1", port) for port in range(1, 35)]
        self.assertLess(scores[0], scores[-1])
        self.assertLessEqual(scores[-1], 1.0)

    def test_dos_score_high_rate(self):
        score = _dos_score(flow_rate=2000, inter_arrival=0.0001)
        self.assertGreater(score, 0.5)

    def test_dos_score_low_rate(self):
        score = _dos_score(flow_rate=5, inter_arrival=1.0)
        self.assertLess(score, 0.3)

    def test_extract_features_no_ip(self):
        """Non-IP packet should return None."""
        mock_pkt = MagicMock()
        mock_pkt.haslayer.return_value = False
        result = extract_features(mock_pkt)
        self.assertIsNone(result)

    def test_feature_columns_complete(self):
        """FEATURE_COLUMNS should have 18 entries."""
        self.assertEqual(len(FEATURE_COLUMNS), 18)


class TestFlowTracker(unittest.TestCase):

    def setUp(self):
        reset_flow_tracker()

    def test_reset_clears_state(self):
        _port_scan_score("192.168.1.1", 80)
        _port_scan_score("192.168.1.1", 443)
        reset_flow_tracker()
        score = _port_scan_score("192.168.1.1", 22)
        self.assertLess(score, 0.1)  # Should be near 0 after reset


if __name__ == "__main__":
    unittest.main()
