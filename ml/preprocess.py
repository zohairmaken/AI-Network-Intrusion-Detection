# =============================================================================
# ml/preprocess.py
# Data preprocessing pipeline for NIDS datasets
# =============================================================================

import os
import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
import joblib

from config.paths import (
    CICIDS_PATH, NSL_KDD_PATH, CLEANED_DATA_PATH,
    ENCODED_DATA_PATH, SCALER_PATH, ENCODER_PATH, SAMPLE_TRAFFIC_PATH
)
from config.constants import FEATURE_COLUMNS, ALL_CLASSES
from config.config import TEST_SIZE, RANDOM_SEED
import core.logger as log

# ─── Column name mappings for CICIDS2017 ─────────────────────────────────────
CICIDS_RENAME = {
    " Flow Duration":         "duration",
    " Protocol":              "protocol_type",
    " Source Port":           "src_port",
    " Destination Port":      "dst_port",
    " Total Length of Fwd Packets": "byte_count",
    " Fwd Packet Length Max": "pkt_length",
    " Flow Packets/s":        "flow_rate",
    " Flow IAT Mean":         "inter_arrival_time",
    " SYN Flag Count":        "flag_syn",
    " ACK Flag Count":        "flag_ack",
    " FIN Flag Count":        "flag_fin",
    " RST Flag Count":        "flag_rst",
    " PSH Flag Count":        "flag_psh",
    " URG Flag Count":        "flag_urg",
    " Total Fwd Packets":     "pkt_count",
    " Label":                 "label"
}

# ─── Column name mappings for NSL-KDD ────────────────────────────────────────
NSL_KDD_COLUMNS = [
    "duration", "protocol_type_str", "service", "flag_str",
    "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent",
    "hot", "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count",
    "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "label", "difficulty"
]

# ─── Label normalization ──────────────────────────────────────────────────────
CICIDS_LABEL_MAP = {
    "BENIGN":              "NORMAL",
    "DoS Hulk":            "DoS Attack",
    "DoS GoldenEye":       "DoS Attack",
    "DoS slowloris":       "DoS Attack",
    "DoS Slowhttptest":    "DoS Attack",
    "DDoS":                "DoS Attack",
    "PortScan":            "Port Scan",
    "FTP-Patator":         "Brute Force",
    "SSH-Patator":         "Brute Force",
    "Bot":                 "Suspicious Activity",
    "Web Attack – Brute Force": "Brute Force",
    "Web Attack – XSS":    "Suspicious Activity",
    "Web Attack – Sql Injection": "Suspicious Activity",
    "Infiltration":        "Suspicious Activity",
    "Heartbleed":          "Suspicious Activity"
}

NSL_KDD_LABEL_MAP = {
    "normal": "NORMAL",
    "neptune": "DoS Attack", "teardrop": "DoS Attack",
    "back": "DoS Attack", "land": "DoS Attack",
    "pod": "DoS Attack", "smurf": "DoS Attack",
    "ipsweep": "Port Scan", "nmap": "Port Scan",
    "portsweep": "Port Scan", "satan": "Port Scan",
    "guess_passwd": "Brute Force", "ftp_write": "Brute Force",
    "imap": "Brute Force", "multihop": "Brute Force",
    "phf": "Brute Force", "spy": "Brute Force",
    "warezclient": "Brute Force", "warezmaster": "Brute Force",
    "buffer_overflow": "Suspicious Activity",
    "loadmodule": "Suspicious Activity",
    "perl": "Suspicious Activity", "rootkit": "Suspicious Activity"
}


def generate_synthetic_dataset(n_samples: int = 10000) -> pd.DataFrame:
    """
    Generate a realistic synthetic dataset for training when real datasets
    are unavailable. Uses class-conditional statistical distributions.
    """
    np.random.seed(RANDOM_SEED)
    rng = np.random.default_rng(RANDOM_SEED)

    rows = []
    class_configs = {
        "NORMAL":              {"n": int(n_samples * 0.50), "flow_rate": (10, 5),   "pkt_len": (512, 200),  "ps_score": (0.02, 0.01), "dos_score": (0.02, 0.01)},
        "DoS Attack":          {"n": int(n_samples * 0.20), "flow_rate": (800, 200), "pkt_len": (64, 10),    "ps_score": (0.05, 0.02), "dos_score": (0.85, 0.10)},
        "Port Scan":           {"n": int(n_samples * 0.15), "flow_rate": (50, 20),   "pkt_len": (64, 10),    "ps_score": (0.80, 0.15), "dos_score": (0.05, 0.02)},
        "Brute Force":         {"n": int(n_samples * 0.10), "flow_rate": (30, 10),   "pkt_len": (200, 50),   "ps_score": (0.10, 0.05), "dos_score": (0.15, 0.05)},
        "Suspicious Activity": {"n": int(n_samples * 0.05), "flow_rate": (20, 8),    "pkt_len": (300, 100),  "ps_score": (0.20, 0.10), "dos_score": (0.20, 0.10)}
    }

    for label, cfg in class_configs.items():
        n = cfg["n"]
        data = {
            "duration":           rng.exponential(10, n),
            "protocol_type":      rng.choice([6, 17, 1], n, p=[0.7, 0.25, 0.05]),
            "src_port":           rng.integers(1024, 65535, n),
            "dst_port":           rng.choice([22, 80, 443, 21, 3306, 8080, 53, 3389], n),
            "pkt_length":         np.clip(rng.normal(*cfg["pkt_len"], n), 20, 65535),
            "flag_syn":           rng.integers(0, 2, n),
            "flag_ack":           rng.integers(0, 2, n),
            "flag_fin":           rng.integers(0, 2, n),
            "flag_rst":           rng.integers(0, 2, n),
            "flag_psh":           rng.integers(0, 2, n),
            "flag_urg":           rng.integers(0, 2, n),
            "pkt_count":          rng.integers(1, 500, n),
            "byte_count":         rng.integers(64, 1000000, n),
            "flow_rate":          np.clip(rng.normal(*cfg["flow_rate"], n), 0.1, 5000),
            "inter_arrival_time": rng.exponential(0.1, n),
            "is_sensitive_port":  rng.integers(0, 2, n),
            "port_scan_score":    np.clip(rng.normal(*cfg["ps_score"], n), 0, 1),
            "dos_score":          np.clip(rng.normal(*cfg["dos_score"], n), 0, 1),
            "label":              [label] * n,
            # Metadata for demo
            "src_ip":             [f"192.168.{rng.integers(1,255)}.{rng.integers(1,255)}" for _ in range(n)],
            "dst_ip":             [f"10.0.{rng.integers(0,10)}.{rng.integers(1,50)}" for _ in range(n)]
        }
        rows.append(pd.DataFrame(data))

    df = pd.concat(rows, ignore_index=True)
    df = df.sample(frac=1, random_state=RANDOM_SEED).reset_index(drop=True)
    return df


def load_raw_dataset(prefer: str = "synthetic") -> pd.DataFrame:
    """
    Load dataset from file or generate synthetic data.

    Args:
        prefer: 'cicids', 'nslkdd', or 'synthetic'

    Returns:
        Raw DataFrame with at least FEATURE_COLUMNS + 'label'
    """
    if prefer == "cicids" and os.path.exists(CICIDS_PATH):
        log.info("Loading CICIDS2017 dataset...")
        df = pd.read_csv(CICIDS_PATH, low_memory=False)
        df = df.rename(columns=CICIDS_RENAME)
        df["label"] = df["label"].map(CICIDS_LABEL_MAP).fillna("Suspicious Activity")
        log.info("CICIDS2017 loaded: %d rows", len(df))
        return df

    if prefer == "nslkdd" and os.path.exists(NSL_KDD_PATH):
        log.info("Loading NSL-KDD dataset...")
        df = pd.read_csv(NSL_KDD_PATH, header=None, names=NSL_KDD_COLUMNS)
        df["label"] = df["label"].str.strip(".").map(NSL_KDD_LABEL_MAP).fillna("Suspicious Activity")
        log.info("NSL-KDD loaded: %d rows", len(df))
        return df

    log.info("Generating synthetic training dataset (10,000 samples)...")
    return generate_synthetic_dataset(10000)


def clean_data(df: pd.DataFrame) -> pd.DataFrame:
    """
    Clean raw dataset:
      - Drop duplicates
      - Handle infinities
      - Fill missing values
      - Keep only required columns
    """
    log.info("Cleaning dataset (%d rows)...", len(df))

    # Drop duplicates
    df = df.drop_duplicates()

    # Keep required columns (plus label)
    cols_needed = FEATURE_COLUMNS + ["label"]
    existing    = [c for c in cols_needed if c in df.columns]
    missing     = [c for c in FEATURE_COLUMNS if c not in df.columns]
    if missing:
        log.warning("Missing columns filled with 0: %s", missing)
        for col in missing:
            df[col] = 0.0

    df = df[cols_needed] if all(c in df.columns for c in cols_needed) else df

    # Replace inf
    df = df.replace([np.inf, -np.inf], np.nan)

    # Fill numeric NaN with median
    num_cols = df.select_dtypes(include=np.number).columns
    for col in num_cols:
        df[col] = df[col].fillna(df[col].median())

    # Fill categorical NaN
    cat_cols = df.select_dtypes(exclude=np.number).columns
    for col in cat_cols:
        df[col] = df[col].fillna("NORMAL")

    log.info("Cleaning complete. Rows remaining: %d", len(df))
    return df


def encode_labels(df: pd.DataFrame) -> tuple:
    """
    Encode string labels to integers.

    Returns:
        (encoded DataFrame, LabelEncoder)
    """
    le = LabelEncoder()
    le.fit(ALL_CLASSES)
    df = df.copy()
    df["label"] = df["label"].apply(
        lambda x: x if x in ALL_CLASSES else "Suspicious Activity"
    )
    df["label_encoded"] = le.transform(df["label"])
    return df, le


def preprocess_pipeline(prefer: str = "synthetic") -> dict:
    """
    Full preprocessing pipeline.

    Returns dict with:
        X_train, X_test, y_train, y_test, scaler, label_encoder, feature_names
    """
    # Load
    df_raw = load_raw_dataset(prefer=prefer)

    # Clean
    df_clean = clean_data(df_raw)
    os.makedirs(os.path.dirname(CLEANED_DATA_PATH), exist_ok=True)
    df_clean.to_csv(CLEANED_DATA_PATH, index=False)
    log.info("Cleaned data saved → %s", CLEANED_DATA_PATH)

    # Encode
    df_enc, le = encode_labels(df_clean)
    df_enc.to_csv(ENCODED_DATA_PATH, index=False)
    log.info("Encoded data saved → %s", ENCODED_DATA_PATH)

    # Save sample for demo/testing
    sample = df_enc.sample(n=min(500, len(df_enc)), random_state=RANDOM_SEED)
    sample.to_csv(SAMPLE_TRAFFIC_PATH, index=False)

    # Features & labels
    feature_names = [c for c in FEATURE_COLUMNS if c in df_enc.columns]
    X = df_enc[feature_names].values.astype(np.float64)
    y = df_enc["label_encoded"].values

    # Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_SEED, stratify=y
    )

    # Scale
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test  = scaler.transform(X_test)

    # Save scaler & encoder
    os.makedirs(os.path.dirname(SCALER_PATH), exist_ok=True)
    joblib.dump(scaler, SCALER_PATH)
    joblib.dump(le,     ENCODER_PATH)
    log.info("Scaler saved → %s", SCALER_PATH)
    log.info("LabelEncoder saved → %s", ENCODER_PATH)

    return {
        "X_train":       X_train,
        "X_test":        X_test,
        "y_train":       y_train,
        "y_test":        y_test,
        "scaler":        scaler,
        "label_encoder": le,
        "feature_names": feature_names,
        "class_names":   list(le.classes_)
    }
