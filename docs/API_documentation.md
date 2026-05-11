# API Documentation — AI-Powered NIDS

## Core Modules

---

### `core.feature_extractor`

#### `extract_features(packet) -> dict | None`
Extract ML features from a Scapy packet.

**Parameters:**
- `packet` — Scapy packet object

**Returns:**
Dict with 18 feature keys + `_src_ip`, `_dst_ip`, `_protocol` metadata.
Returns `None` for non-IP packets.

#### `features_to_vector(features: dict) -> np.ndarray`
Convert features dict to a numpy array in FEATURE_COLUMNS order.

**Returns:** 1-D float64 array of shape `(18,)`

#### `reset_flow_tracker()`
Clear in-memory flow and port-scan trackers between sessions.

---

### `core.intrusion_detector`

#### `initialize(model_names: list)`
Load models and scaler into memory. Call once at startup.

**Parameters:**
- `model_names` — List of `['random_forest', 'decision_tree', 'xgboost']`

#### `predict(features: dict, model_name: str) -> dict | None`
Run ML prediction on extracted packet features.

**Returns:**
```python
{
  "prediction":  "DoS Attack",    # str: attack class
  "confidence":  0.93,            # float: 0-1
  "severity":    "HIGH",          # str: LOW/MEDIUM/HIGH/CRITICAL
  "risk_score":  0.70,            # float: 0-1
  "action":      "BLOCK",         # str: recommended action
  "src_ip":      "10.0.0.1",
  "dst_ip":      "192.168.1.1",
  "dst_port":    80,
  "is_attack":   True,
  "model_used":  "random_forest"
}
```

#### `predict_from_row(row: dict, model_name: str) -> dict | None`
Predict from a CSV row dict (batch/demo mode).

---

### `core.traffic_monitor`

#### `start_monitoring(interface, model_name, bpf_filter, demo_mode, demo_rows, on_alert, on_packet)`
Start live traffic capture and analysis.

**Parameters:**
- `interface` — Network interface (`None` = auto)
- `model_name` — ML model to use
- `bpf_filter` — Scapy BPF filter string (`"ip"`, `"tcp"`, etc.)
- `demo_mode` — Boolean, replay `demo_rows` instead of live capture
- `demo_rows` — List of dicts for demo mode
- `on_alert` — Callback: `fn(threat_dict)` called on each attack
- `on_packet` — Callback: `fn(packet_dict)` called on each packet

#### `stop_monitoring()`
Stop capture and analysis threads.

#### `get_traffic_stats() -> dict`
Return cumulative traffic statistics.

#### `get_timeline_data() -> dict`
Return `{"labels": [...], "packets": [...], "attacks": [...]}` for charts.

#### `get_recent_alerts(n: int) -> list`
Return last N attack result dicts.

#### `get_recent_packets(n: int) -> list`
Return last N packet summary dicts.

---

### `core.threat_analyzer`

#### `analyze_threat(prediction, confidence, features, is_blacklisted) -> dict`
Full threat analysis pipeline.

**Returns:** Dict including `severity`, `risk_score`, `action`, `is_attack`.

#### `calculate_severity(prediction, confidence, dst_port, ...) -> str`
Calculate severity level: `LOW | MEDIUM | HIGH | CRITICAL`.

---

### `core.logger`

#### `log_attack(src_ip, dst_ip, src_port, dst_port, protocol, pkt_length, prediction, confidence, severity, action)`
Write attack record to `logs/attack_logs.csv`. Thread-safe.

#### `add_to_blacklist(ip: str)`
Add IP to `logs/blacklist.txt`.

#### `load_blacklist() -> set`
Return set of blacklisted IP strings.

#### `read_attack_logs() -> list`
Return all attack log entries as list of dicts.

---

### `app.alert_system`

#### `add_alert(threat_result: dict, on_critical: callable) -> dict | None`
Process threat into alert, store it, optionally send email.

#### `get_alerts(n: int, severity_filter: str) -> list`
Retrieve recent alerts with optional severity filtering.

#### `get_alert_stats() -> dict`
Return `{"total", "critical", "high", "medium", "low", "email_sent"}`.

#### `clear_alerts()`
Clear all in-memory alerts.

---

### `ml.preprocess`

#### `preprocess_pipeline(prefer: str) -> dict`
Full preprocessing pipeline. Returns:
```python
{
  "X_train": np.ndarray,
  "X_test":  np.ndarray,
  "y_train": np.ndarray,
  "y_test":  np.ndarray,
  "scaler":  StandardScaler,
  "label_encoder": LabelEncoder,
  "feature_names": list,
  "class_names":   list
}
```

#### `generate_synthetic_dataset(n_samples: int) -> pd.DataFrame`
Generate a realistic synthetic NIDS dataset.

---

### `ml.train_model`

#### `train_and_evaluate(prefer_dataset: str) -> dict`
Full pipeline: preprocess → train all models → evaluate → save.

**Returns:** `{model_name: metrics_dict}` for all trained models.

---

### `ml.evaluate_model`

#### `compute_metrics(y_true, y_pred, class_names) -> dict`
Returns `{"accuracy", "precision", "recall", "f1_score", "report"}`.

#### `plot_confusion_matrix(y_true, y_pred, class_names, save_path) -> str`
Save styled confusion matrix PNG. Returns path.

#### `plot_accuracy_comparison(results: dict, save_path) -> str`
Save multi-model accuracy bar chart. Returns path.

#### `plot_roc_curves(model, X_test, y_test, class_names, save_path) -> str`
Save OvR ROC curve chart. Returns path.

---

## Configuration Keys (`config/config.py`)

| Key | Default | Description |
|-----|---------|-------------|
| `SNIFF_INTERFACE` | `None` | Network interface (None = auto) |
| `MAX_PACKETS_PER_SESSION` | `1000` | Max packets per capture run |
| `N_ESTIMATORS` | `200` | Random Forest tree count |
| `ALERT_THRESHOLD_HIGH` | `0.85` | Confidence cutoff for HIGH severity |
| `EMAIL_ALERTS_ENABLED` | `False` | Enable email notifications |
| `AUTH_ENABLED` | `True` | Enable login page |
| `BLACKLIST_AUTO_ADD` | `True` | Auto-blacklist repeat attackers |
| `BLACKLIST_THRESHOLD` | `3` | Attacks before auto-blacklist |
| `DASHBOARD_REFRESH_INTERVAL` | `3` | Dashboard auto-refresh (seconds) |
