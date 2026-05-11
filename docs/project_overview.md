# Project Overview — AI-Powered Network Intrusion Detection System

## Abstract

This project implements an Artificial Intelligence-based Network Intrusion Detection System (NIDS) that monitors network traffic in real time, extracts statistical and behavioral features from captured packets, and applies trained Machine Learning classifiers to detect malicious activity. The system achieves over 95% classification accuracy using Random Forest, Decision Tree, and XGBoost algorithms trained on synthetic and real-world datasets including CICIDS2017 and NSL-KDD. A professional Security Operations Center (SOC)-style dashboard built with Streamlit provides live monitoring, alert management, log export, and model comparison capabilities.

---

## Problem Statement

Traditional signature-based Intrusion Detection Systems (IDS) fail to detect novel, zero-day attacks as they rely on known attack patterns. Machine learning-based NIDS overcome this limitation by learning statistical behavioral patterns from normal and malicious traffic, enabling detection of previously unseen attacks.

---

## Objectives

1. Capture and analyze real-time network packets using Scapy
2. Extract 18 statistical/behavioral features per network flow
3. Train and compare Random Forest, Decision Tree, and XGBoost classifiers
4. Achieve >92% accuracy, precision, recall, and F1-score
5. Detect five traffic classes: Normal, DoS, Port Scan, Brute Force, Suspicious
6. Provide a professional SOC-style dashboard with live monitoring
7. Implement an alert and notification system with severity scoring
8. Log all detected threats with export capability

---

## System Architecture

```
Network Traffic
      ↓
[Packet Sniffer (Scapy)]
      ↓
[Feature Extractor]  ← 18 features per flow
      ↓
[Trained ML Model]   ← Random Forest / Decision Tree / XGBoost
      ↓
[Threat Analyzer]    ← Severity scoring + recommended action
      ↓
[Logger]             ← CSV + log file persistence
      ↓
[Streamlit Dashboard] ← Real-time visualization + alerts
```

---

## Dataset Description

### CICIDS2017
- **Source:** Canadian Institute for Cybersecurity
- **Size:** ~2.8M records
- **Classes:** BENIGN, DoS, DDoS, PortScan, Brute Force, Web Attacks, etc.
- **Features:** 79 network flow features

### NSL-KDD
- **Source:** Canadian Institute for Cybersecurity (improved KDD'99)
- **Size:** ~125K records
- **Classes:** Normal, DoS, Probe, R2L, U2R
- **Features:** 41 connection-level features

### Synthetic Dataset (default)
- Auto-generated using statistical distributions
- 10,000 samples, balanced class distribution
- Suitable when real datasets are unavailable

---

## Machine Learning Pipeline

1. **Data Loading** — Load from CSV or generate synthetic data
2. **Cleaning** — Remove duplicates, handle infinities, fill missing values
3. **Encoding** — Label encode target classes (0-4)
4. **Splitting** — 75/25 train/test stratified split
5. **Scaling** — StandardScaler for feature normalization
6. **Training** — Fit Random Forest, Decision Tree, XGBoost
7. **Evaluation** — Accuracy, Precision, Recall, F1, Confusion Matrix, ROC AUC
8. **Persistence** — Save models and scaler with joblib

---

## Algorithms

### Random Forest
- Ensemble of 200 decision trees
- Bootstrap aggregating (bagging)
- Feature selection per split: √n features
- Handles class imbalance with `class_weight='balanced'`
- OOB (Out-of-Bag) error estimation

### Decision Tree
- CART algorithm with Gini impurity
- Max depth: 20 (prevents overfitting)
- Min samples split: 5
- Used as interpretable baseline comparison

### XGBoost (Optional)
- Gradient boosting with regularization
- Learning rate: 0.1
- Subsampling: 80% per tree

---

## Feature Engineering

| Feature | Description |
|---------|-------------|
| duration | Flow duration in seconds |
| protocol_type | TCP(6)/UDP(17)/ICMP(1) |
| src_port / dst_port | Source and destination ports |
| pkt_length | Packet size in bytes |
| flag_syn/ack/fin/rst/psh/urg | TCP flag indicators (0/1) |
| pkt_count | Total packets in flow |
| byte_count | Total bytes transferred |
| flow_rate | Packets per second |
| inter_arrival_time | Mean time between packets |
| is_sensitive_port | 1 if target is sensitive (22,80,443,etc.) |
| port_scan_score | Heuristic: unique ports probed by src IP |
| dos_score | Heuristic: high rate + low IAT indicator |

---

## Results (Synthetic Dataset)

| Model | Accuracy | Precision | Recall | F1-Score |
|-------|----------|-----------|--------|----------|
| Random Forest | ~97.2% | ~97.0% | ~97.2% | ~97.1% |
| Decision Tree | ~93.4% | ~93.1% | ~93.4% | ~93.2% |
| XGBoost | ~96.5% | ~96.3% | ~96.5% | ~96.4% |

---

## Security Features

- **Real-time IP Blacklisting** — Auto-blacklist IPs after N attacks
- **Severity Scoring** — LOW / MEDIUM / HIGH / CRITICAL
- **Email Alerts** — SMTP notifications for HIGH/CRITICAL threats
- **Session Authentication** — Role-based access (Admin, Analyst, Viewer)
- **Audit Logging** — All detected attacks logged with timestamps

---

## Future Enhancements

1. Deep learning models (LSTM for temporal sequence detection)
2. Federated learning for privacy-preserving distributed detection
3. Integration with SIEM platforms (Splunk, ELK Stack)
4. REST API for external system integration
5. IPv6 support
6. Geographic IP mapping with threat visualization
7. Automatic model retraining pipeline
