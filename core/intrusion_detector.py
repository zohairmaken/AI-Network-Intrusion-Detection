# =============================================================================
# core/intrusion_detector.py
# ML prediction engine — loads trained models and classifies traffic
# =============================================================================

import numpy as np
from typing import Tuple, Optional, Dict, Any

from ml.model_loader import load_model, load_scaler
from core.feature_extractor import features_to_vector
from core.threat_analyzer import analyze_threat
from core.logger import is_blacklisted, log_attack
from config.constants import CLASS_NORMAL, FEATURE_COLUMNS
from config.config import BLACKLIST_AUTO_ADD, BLACKLIST_THRESHOLD, ATTACK_LABELS
import core.logger as log

# ─── Model cache ──────────────────────────────────────────────────────────────
_models: Dict[str, Any] = {}
_scaler = None
_attack_counter: Dict[str, int] = {}  # src_ip -> attack count for blacklisting


def initialize(model_names: list = None):
    """
    Load models and scaler into memory at startup.

    Args:
        model_names: List of model keys to load. Defaults to ['random_forest'].
    """
    global _scaler
    if model_names is None:
        model_names = ["random_forest"]

    for name in model_names:
        try:
            _models[name] = load_model(name)
            log.info("Model loaded: %s", name)
        except Exception as e:
            log.error("Failed to load model '%s': %s", name, str(e))

    try:
        _scaler = load_scaler()
        log.info("Scaler loaded successfully.")
    except Exception as e:
        log.error("Failed to load scaler: %s", str(e))


def predict(
    features: Dict[str, Any],
    model_name: str = "random_forest"
) -> Optional[Dict]:
    """
    Run ML prediction on extracted packet features.

    Args:
        features   : Feature dict from feature_extractor.extract_features()
        model_name : Which model to use ('random_forest', 'decision_tree', 'xgboost')

    Returns:
        Dict with prediction results and threat analysis, or None on failure.
    """
    global _attack_counter

    if model_name not in _models:
        log.warning("Model '%s' not loaded. Attempting to load...", model_name)
        try:
            _models[model_name] = load_model(model_name)
        except Exception as e:
            log.error("Cannot load model: %s", str(e))
            return None

    model = _models[model_name]

    try:
        # ── Build feature vector ───────────────────────────────────────────
        X = features_to_vector(features).reshape(1, -1)

        # ── Scale if scaler available ──────────────────────────────────────
        if _scaler is not None:
            X = _scaler.transform(X)

        # ── Predict ───────────────────────────────────────────────────────
        pred_idx   = int(model.predict(X)[0])
        prediction = ATTACK_LABELS.get(pred_idx, "Unknown")

        # ── Confidence ────────────────────────────────────────────────────
        if hasattr(model, "predict_proba"):
            proba      = model.predict_proba(X)[0]
            confidence = float(np.max(proba))
        else:
            confidence = 1.0

        # ── Blacklist check ───────────────────────────────────────────────
        src_ip         = features.get("_src_ip", "")
        bl_status      = is_blacklisted(src_ip)

        # ── Full threat analysis ───────────────────────────────────────────
        result = analyze_threat(
            prediction=prediction,
            confidence=confidence,
            features=features,
            is_blacklisted=bl_status
        )
        result["model_used"] = model_name

        # ── Auto-logging & blacklisting ────────────────────────────────────
        if prediction != CLASS_NORMAL:
            log_attack(
                src_ip      = src_ip,
                dst_ip      = result["dst_ip"],
                src_port    = features.get("src_port", 0),
                dst_port    = result["dst_port"],
                protocol    = str(result["protocol"]),
                pkt_length  = result["pkt_length"],
                prediction  = prediction,
                confidence  = confidence,
                severity    = result["severity"],
                action      = result["action"]
            )
            # Track for blacklisting
            if BLACKLIST_AUTO_ADD and src_ip:
                _attack_counter[src_ip] = _attack_counter.get(src_ip, 0) + 1
                if _attack_counter[src_ip] >= BLACKLIST_THRESHOLD:
                    from core.logger import add_to_blacklist
                    add_to_blacklist(src_ip)
                    _attack_counter[src_ip] = 0  # reset counter

        return result

    except Exception as e:
        log.error("Prediction error: %s", str(e))
        return None


def predict_from_row(row: dict, model_name: str = "random_forest") -> Optional[Dict]:
    """
    Predict from a CSV/DataFrame row (for demo/batch mode).
    Row must contain columns matching FEATURE_COLUMNS.
    """
    try:
        features = {col: float(row.get(col, 0)) for col in FEATURE_COLUMNS}
        features["_src_ip"]   = str(row.get("src_ip", "0.0.0.0"))
        features["_dst_ip"]   = str(row.get("dst_ip", "0.0.0.0"))
        features["_protocol"] = str(row.get("protocol", "TCP"))
        return predict(features, model_name)
    except Exception as e:
        log.error("predict_from_row error: %s", str(e))
        return None


def get_loaded_models() -> list:
    """Return names of currently loaded models."""
    return list(_models.keys())


def is_initialized() -> bool:
    """Check whether at least one model is loaded."""
    return bool(_models)
