# AI-Powered Network Intrusion Detection System (NIDS)

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python)
![Streamlit](https://img.shields.io/badge/Streamlit-1.32+-red?style=for-the-badge&logo=streamlit)
![ML](https://img.shields.io/badge/ML-Random%20Forest%20%7C%20XGBoost-green?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)

**A production-level AI-powered Network Intrusion Detection System built with Machine Learning, real-time packet sniffing, and a professional SOC-style dashboard.**

</div>

---

## 📌 Project Overview

This system detects network intrusions in real time using trained Machine Learning models. It captures live network packets, extracts meaningful features, classifies traffic as normal or malicious, and visualizes everything through a professional dark-themed Streamlit dashboard.

### Detected Attack Types
| Class | Description |
|-------|-------------|
| ✅ NORMAL | Legitimate network traffic |
| 🔴 DoS Attack | Denial of Service / DDoS floods |
| 🟠 Port Scan | Reconnaissance scanning activity |
| 🔴 Brute Force | Password / credential brute forcing |
| 🟡 Suspicious Activity | Anomalous / unclassified threats |

---

## 🚀 Quick Start

### 1. Install Dependencies
```bash
cd AI_Network_Intrusion_Detection_System
pip install -r requirements.txt
```

### 2. Run the Project
```bash
# Auto-trains models and launches dashboard
python run.py

# Or: train first with specific dataset
python run.py --train --dataset synthetic

# Or: train only (no dashboard)
python run.py --train-only
```

### 3. Access Dashboard
Open your browser at: **http://localhost:8501**

**Default credentials:** `admin` / `nids@2024`

---

## 🏗 Architecture

```
AI_Network_Intrusion_Detection_System/
│
├── app/                    # Streamlit UI layer
│   ├── app.py              # Main dashboard (7 pages)
│   ├── dashboard.py        # Plotly charts & UI components
│   ├── authentication.py   # Session-based auth
│   ├── alert_system.py     # Alert management + email
│   └── utils.py            # Helper utilities
│
├── core/                   # Detection engine
│   ├── packet_sniffer.py   # Scapy real-time capture
│   ├── feature_extractor.py# Packet → ML features
│   ├── intrusion_detector.py# ML prediction engine
│   ├── traffic_monitor.py  # Orchestration layer
│   ├── threat_analyzer.py  # Severity scoring
│   └── logger.py           # Attack logging
│
├── ml/                     # Machine Learning
│   ├── train_model.py      # Training pipeline
│   ├── preprocess.py       # Data preprocessing
│   ├── evaluate_model.py   # Metrics & visualizations
│   ├── model_loader.py     # Model persistence
│   ├── feature_selection.py# Feature analysis
│   └── algorithms/         # Model implementations
│       ├── random_forest.py
│       ├── decision_tree.py
│       └── xgboost_model.py
│
├── config/                 # Configuration
│   ├── config.py           # Global settings
│   ├── constants.py        # Constants & labels
│   └── paths.py            # File paths
│
├── models/                 # Saved model files (.pkl)
├── dataset/                # Training datasets
├── logs/                   # Attack & system logs
├── visualizations/         # Generated charts
├── tests/                  # Unit tests
├── docs/                   # Documentation
├── requirements.txt
└── run.py                  # Entry point
```

---

## 🤖 Machine Learning Models

| Model | Algorithm | Accuracy (Synthetic) |
|-------|-----------|---------------------|
| Random Forest | Ensemble of 200 trees | ~97% |
| Decision Tree | Single CART tree | ~93% |
| XGBoost | Gradient Boosting | ~96% |

### Features Extracted (18 total)
- Duration, Protocol Type, Ports
- Packet Length, TCP Flags (SYN/ACK/FIN/RST/PSH/URG)
- Packet Count, Byte Count, Flow Rate
- Inter-Arrival Time, Port Scan Score, DoS Score
- Sensitive Port Flag

---

## 📊 Dashboard Pages

| Page | Description |
|------|-------------|
| 🏠 Dashboard | KPI cards, live charts, recent alerts |
| 📡 Live Monitor | Real-time packet feed table |
| 🚨 Alerts | Alert management with severity filtering |
| 🤖 ML Models | Train, evaluate, compare models |
| 📊 Analytics | Attack distribution & log charts |
| 📋 Logs | Downloadable attack logs (CSV/JSON) |
| ⚙️ Settings | Network config, email alerts, system info |

---

## 🔧 Configuration

Edit `config/config.py` to customize:
- `SNIFF_INTERFACE` — network interface (None = auto)
- `N_ESTIMATORS` — Random Forest trees (default: 200)
- `ALERT_THRESHOLD_HIGH` — confidence for HIGH severity (0.85)
- `EMAIL_ALERTS_ENABLED` — enable email notifications
- `AUTH_ENABLED` — enable/disable login page
- `BLACKLIST_AUTO_ADD` — auto-blacklist repeat attackers

---

## 🧪 Running Tests

```bash
# Run all tests
python -m pytest tests/ -v

# Run specific test file
python -m pytest tests/test_model.py -v
python -m pytest tests/test_feature_extraction.py -v
python -m pytest tests/test_dashboard.py -v
```

---

## 📧 Email Alerts (Optional)

Set in `config/config.py`:
```python
EMAIL_ALERTS_ENABLED = True
SENDER_EMAIL = "your@gmail.com"
RECEIVER_EMAIL = "admin@yourorg.com"
EMAIL_APP_PASSWORD = "your-gmail-app-password"
```

---

## 📁 Dataset Support

| Dataset | Status | Notes |
|---------|--------|-------|
| Synthetic | ✅ Auto-generated | 10,000 samples, all classes |
| CICIDS2017 | ✅ Supported | Place CSV in `dataset/raw/CICIDS2017.csv` |
| NSL-KDD | ✅ Supported | Place CSV in `dataset/raw/NSL_KDD.csv` |

---

## 👥 User Accounts

| Username | Password | Role |
|----------|----------|------|
| admin | nids@2024 | Administrator |
| analyst | analyst@2024 | Security Analyst |
| viewer | view@2024 | Read-Only Viewer |

---

## 📋 Requirements

- Python 3.10+
- Windows / Linux / macOS
- **Admin/root privileges** required for live packet capture
- Npcap (Windows) or libpcap (Linux/macOS) for Scapy

---

## 📄 License

MIT License — See [LICENSE](LICENSE) for details.

---

## 🎓 Academic Use

This project is designed for:
- University final-year project submission
- Cybersecurity portfolio demonstration
- SOC (Security Operations Center) simulation
- ML in network security research

**Project:** AI-Powered Network Intrusion Detection System  
**Subject:** Information Security / Cybersecurity  
**Tech Stack:** Python, Streamlit, Scikit-learn, Scapy, Plotly
