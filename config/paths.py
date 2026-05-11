# =============================================================================
# config/paths.py
# Centralized file/folder path management
# =============================================================================

import os

# ─── Base Directory ───────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ─── Core Directories ────────────────────────────────────────────────────────
APP_DIR          = os.path.join(BASE_DIR, "app")
CORE_DIR         = os.path.join(BASE_DIR, "core")
ML_DIR           = os.path.join(BASE_DIR, "ml")
MODELS_DIR       = os.path.join(BASE_DIR, "models")
DATASET_DIR      = os.path.join(BASE_DIR, "dataset")
LOGS_DIR         = os.path.join(BASE_DIR, "logs")
VIZ_DIR          = os.path.join(BASE_DIR, "visualizations")
REPORTS_DIR      = os.path.join(BASE_DIR, "reports")
CONFIG_DIR       = os.path.join(BASE_DIR, "config")
TESTS_DIR        = os.path.join(BASE_DIR, "tests")
DOCS_DIR         = os.path.join(BASE_DIR, "docs")

# ─── Dataset Paths ────────────────────────────────────────────────────────────
RAW_DATA_DIR        = os.path.join(DATASET_DIR, "raw")
PROCESSED_DATA_DIR  = os.path.join(DATASET_DIR, "processed")
SAMPLE_PACKETS_DIR  = os.path.join(DATASET_DIR, "sample_packets")

CICIDS_PATH         = os.path.join(RAW_DATA_DIR, "CICIDS2017.csv")
NSL_KDD_PATH        = os.path.join(RAW_DATA_DIR, "NSL_KDD.csv")
CLEANED_DATA_PATH   = os.path.join(PROCESSED_DATA_DIR, "cleaned_data.csv")
ENCODED_DATA_PATH   = os.path.join(PROCESSED_DATA_DIR, "encoded_data.csv")
SAMPLE_TRAFFIC_PATH = os.path.join(SAMPLE_PACKETS_DIR, "sample_traffic.csv")

# ─── Model Paths ──────────────────────────────────────────────────────────────
RF_MODEL_PATH   = os.path.join(MODELS_DIR, "random_forest_model.pkl")
DT_MODEL_PATH   = os.path.join(MODELS_DIR, "decision_tree_model.pkl")
XGB_MODEL_PATH  = os.path.join(MODELS_DIR, "xgboost_model.pkl")
SCALER_PATH     = os.path.join(MODELS_DIR, "scaler.pkl")
ENCODER_PATH    = os.path.join(MODELS_DIR, "label_encoder.pkl")

# ─── Log Paths ────────────────────────────────────────────────────────────────
ATTACK_LOG_PATH     = os.path.join(LOGS_DIR, "attack_logs.csv")
SUSPICIOUS_LOG_PATH = os.path.join(LOGS_DIR, "suspicious_activity.log")
SYSTEM_LOG_PATH     = os.path.join(LOGS_DIR, "system_logs.log")
BLACKLIST_PATH      = os.path.join(LOGS_DIR, "blacklist.txt")

# ─── Visualization Paths ──────────────────────────────────────────────────────
CONFUSION_MATRIX_PATH     = os.path.join(VIZ_DIR, "confusion_matrix.png")
ACCURACY_GRAPH_PATH       = os.path.join(VIZ_DIR, "accuracy_graph.png")
ATTACK_DIST_PATH          = os.path.join(VIZ_DIR, "attack_distribution.png")
LIVE_TRAFFIC_GRAPH_PATH   = os.path.join(VIZ_DIR, "live_traffic_graph.png")
FEATURE_IMPORTANCE_PATH   = os.path.join(VIZ_DIR, "feature_importance.png")
ROC_CURVE_PATH            = os.path.join(VIZ_DIR, "roc_curve.png")

# ─── Report Paths ─────────────────────────────────────────────────────────────
SCREENSHOTS_DIR  = os.path.join(REPORTS_DIR, "screenshots")
FINAL_REPORT     = os.path.join(REPORTS_DIR, "final_report.docx")
ARCHITECTURE_IMG = os.path.join(REPORTS_DIR, "architecture_diagram.png")
FLOWCHART_IMG    = os.path.join(REPORTS_DIR, "flowchart.png")


def ensure_dirs():
    """Create all necessary directories if they don't exist."""
    dirs = [
        APP_DIR, CORE_DIR, ML_DIR, MODELS_DIR, DATASET_DIR,
        LOGS_DIR, VIZ_DIR, REPORTS_DIR, CONFIG_DIR, TESTS_DIR, DOCS_DIR,
        RAW_DATA_DIR, PROCESSED_DATA_DIR, SAMPLE_PACKETS_DIR, SCREENSHOTS_DIR
    ]
    for d in dirs:
        os.makedirs(d, exist_ok=True)
