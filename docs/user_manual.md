# User Manual — AI-Powered NIDS

## 1. Introduction

Welcome to the AI-Powered Network Intrusion Detection System (NIDS). This system acts as a smart sentry for your network, continuously analyzing traffic to identify malicious activities such as Denial of Service (DoS) attacks, Port Scans, and Brute Force attempts.

This manual will guide you through using the Streamlit-based Security Operations Center (SOC) dashboard.

---

## 2. Getting Started

### Starting the System
1. Open your terminal or command prompt.
2. Navigate to the project directory: `cd AI_Network_Intrusion_Detection_System`
3. Run the startup script: `python run.py`
4. A browser window will automatically open to `http://localhost:8501`.

### Logging In
You will be greeted by the secure login portal.
- **Username:** `admin`
- **Password:** `nids@2024`

*(Note: These default credentials can be changed in `app/authentication.py`)*

---

## 3. Dashboard Overview

The application is divided into several main pages, accessible via the left sidebar.

### 🏠 Dashboard
The main overview screen.
- **Top KPI Cards:** Shows total packets, detected attacks, packets per second (PPS), and total alerts.
- **Live Traffic Monitor:** A real-time line chart comparing normal vs. attack traffic.
- **Traffic Distribution:** A donut chart showing the breakdown of traffic by class.
- **Threat Level Gauge:** A 0-100% dial indicating the current risk score of the network.
- **Recent Alerts:** A quick-glance table of the most recent security alerts.

### 📡 Live Monitor
The raw data feed.
- Starts automatically when monitoring is active.
- Displays a rolling table of the last 30 packets analyzed.
- Highlights malicious packets in red, orange, or yellow depending on severity.

### 🚨 Alerts
The incident response center.
- Filter alerts by severity (CRITICAL, HIGH, MEDIUM, LOW).
- View confidence scores, source/destination IPs, and recommended actions.
- Use the **Clear All Alerts** button to reset the queue.

### 🤖 ML Models
Manage the system's brain.
- **Train Models:** Retrain the models on a selected dataset (Synthetic, CICIDS, NSL-KDD).
- **Performance:** View grouped bar charts comparing Accuracy, Precision, Recall, and F1-Score across Random Forest, Decision Tree, and XGBoost.
- **Visualizations:** View generated confusion matrices, feature importance charts, and ROC curves.

### 📊 Analytics
Historical attack analysis.
- View bar charts of attack types and pie charts of severities based on historical logs.
- Export raw log data to CSV for external analysis.

### 📋 Logs
System audit trail.
- View the complete `attack_logs.csv` directly in the browser.
- Download logs in CSV or JSON format.

### ⚙️ Settings
System configuration and status.
- View available network interfaces and their IPs.
- Monitor host system CPU, RAM, and Disk usage.
- View instructions for setting up Email Alerts.

---

## 4. Operating the Monitor

In the left sidebar, under **🎛 Monitor Controls**:

1. **Demo Mode Checkbox:** 
   - If checked, the system replays sample traffic from a CSV file (great for testing and demonstrations).
   - If unchecked, the system attempts to capture live packets from your network interface (Requires Administrator/Root privileges).

2. **ML Model Dropdown:** 
   - Select which model to use for prediction (Random Forest is recommended for the best balance of speed and accuracy).

3. **▶ Start / ⏹ Stop Buttons:**
   - Click Start to begin analyzing traffic. The "Status" indicator will turn green (`● LIVE`).
   - Click Stop to pause analysis.

---

## 5. Responding to Threats

When a threat is detected, it is assigned a **Severity** and a **Recommended Action**:

- **CRITICAL (e.g., Brute Force, high-rate DoS):** Immediate action required. The system recommends blocking the IP. If email alerts are enabled, an email is sent to the administrator.
- **HIGH:** Strong indicator of attack. Consider temporary IP blocks or rate limiting.
- **MEDIUM (e.g., Port Scan):** Reconnaissance activity. Log and monitor the source IP for escalation.
- **LOW:** Suspicious anomalous traffic. Logged for future auditing.

---

## 6. Troubleshooting

- **Dashboard is blank or not loading:** Ensure you ran `python run.py` and that no errors appeared in the terminal.
- **"Model not loaded" error:** Go to the `🤖 ML Models` page and click "Start Training" to generate the `.pkl` files.
- **Live capture not working:** Ensure you launched the terminal as Administrator (Windows) or using `sudo` (Linux/Mac). Also, ensure Npcap/libpcap is installed.
