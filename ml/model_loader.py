# =============================================================================
# ml/model_loader.py
# Load trained models and scaler from disk
# =============================================================================

import os
import joblib
from config.paths import RF_MODEL_PATH, DT_MODEL_PATH, XGB_MODEL_PATH, SCALER_PATH, ENCODER_PATH
import core.logger as log

_MODEL_PATHS = {
    "random_forest":  RF_MODEL_PATH,
    "decision_tree":  DT_MODEL_PATH,
    "xgboost":        XGB_MODEL_PATH
}


def load_model(model_name: str = "random_forest"):
    """
    Load a trained model from disk.

    Args:
        model_name: 'random_forest', 'decision_tree', or 'xgboost'

    Returns:
        Loaded sklearn/xgboost model object

    Raises:
        FileNotFoundError if model file doesn't exist
        RuntimeError if model_name is unknown
    """
    if model_name not in _MODEL_PATHS:
        raise RuntimeError(
            f"Unknown model: '{model_name}'. "
            f"Valid options: {list(_MODEL_PATHS.keys())}"
        )
    path = _MODEL_PATHS[model_name]
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"Model file not found: {path}\n"
            f"Run 'python ml/train_model.py' first to train models."
        )
    model = joblib.load(path)
    log.info("Loaded model '%s' from %s", model_name, path)
    return model


def load_scaler():
    """
    Load the fitted StandardScaler from disk.

    Returns:
        StandardScaler object

    Raises:
        FileNotFoundError if scaler file doesn't exist
    """
    if not os.path.exists(SCALER_PATH):
        raise FileNotFoundError(
            f"Scaler not found: {SCALER_PATH}\n"
            f"Run 'python ml/train_model.py' first."
        )
    scaler = joblib.load(SCALER_PATH)
    log.info("Scaler loaded from %s", SCALER_PATH)
    return scaler


def load_label_encoder():
    """
    Load the fitted LabelEncoder from disk.

    Returns:
        LabelEncoder object
    """
    if not os.path.exists(ENCODER_PATH):
        raise FileNotFoundError(
            f"LabelEncoder not found: {ENCODER_PATH}\n"
            f"Run 'python ml/train_model.py' first."
        )
    le = joblib.load(ENCODER_PATH)
    log.info("LabelEncoder loaded from %s", ENCODER_PATH)
    return le


def models_exist() -> dict:
    """
    Check which trained model files exist on disk.

    Returns:
        Dict mapping model_name -> bool
    """
    return {name: os.path.exists(path) for name, path in _MODEL_PATHS.items()}


def save_model(model, model_name: str):
    """
    Save a trained model to disk.

    Args:
        model      : Trained model object
        model_name : One of the known model keys
    """
    if model_name not in _MODEL_PATHS:
        raise RuntimeError(f"Unknown model name: {model_name}")
    path = _MODEL_PATHS[model_name]
    os.makedirs(os.path.dirname(path), exist_ok=True)
    joblib.dump(model, path)
    log.info("Model '%s' saved to %s", model_name, path)
