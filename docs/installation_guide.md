# Installation Guide — AI-Powered NIDS

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | 3.10+ | [python.org](https://www.python.org/downloads/) |
| pip | latest | Comes with Python |
| Npcap (Windows) | latest | Required for Scapy packet capture |
| libpcap (Linux) | latest | `sudo apt install libpcap-dev` |

---

## Step 1 — Clone or Download the Project

```bash
# If using Git
git clone https://github.com/yourname/AI_Network_Intrusion_Detection_System.git
cd AI_Network_Intrusion_Detection_System

# Or navigate to your project folder
cd "C:\Users\zohai\OneDrive\Pictures\IS project\AI_Network_Intrusion_Detection_System"
```

---

## Step 2 — Create a Virtual Environment (Recommended)

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux / macOS
python3 -m venv venv
source venv/bin/activate
```

---

## Step 3 — Install Python Dependencies

```bash
pip install -r requirements.txt
```

This installs:
- `streamlit` — Dashboard UI
- `scikit-learn` — Machine Learning
- `pandas`, `numpy` — Data processing
- `matplotlib`, `seaborn`, `plotly` — Visualizations
- `scapy` — Packet sniffing
- `psutil` — System monitoring
- `joblib` — Model persistence
- `xgboost` — Gradient boosting (optional)

---

## Step 4 — Install Npcap (Windows Only)

Download from: https://npcap.com/#download

During installation:
- ✅ Check "Install Npcap in WinPcap API-compatible Mode"
- ✅ Check "Support raw 802.11 traffic"

> **Note:** On Linux/macOS, install libpcap:
> ```bash
> sudo apt install libpcap-dev   # Ubuntu/Debian
> sudo yum install libpcap-devel # CentOS/RHEL
> brew install libpcap           # macOS
> ```

---

## Step 5 — Run the Project

```bash
# Option A: Auto (trains models + launches dashboard)
python run.py

# Option B: Train first, then launch
python run.py --train

# Option C: Use real dataset
python run.py --train --dataset cicids
```

---

## Step 6 — Access the Dashboard

Open browser → **http://localhost:8501**

Login with:
- Username: `admin`
- Password: `nids@2024`

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `ModuleNotFoundError: scapy` | `pip install scapy` |
| `PermissionError` during capture | Run as Administrator / sudo |
| `No module named 'xgboost'` | `pip install xgboost` (optional) |
| Port 8501 in use | Change port: `streamlit run app/app.py --server.port 8502` |
| Scapy can't find interface | Install Npcap (Windows) or libpcap (Linux) |
| Model not found error | Run `python run.py --train` first |

---

## Running Tests

```bash
# All tests
python -m pytest tests/ -v --tb=short

# Individual
python -m pytest tests/test_model.py -v
python -m pytest tests/test_feature_extraction.py -v
python -m pytest tests/test_dashboard.py -v
python -m pytest tests/test_sniffer.py -v
```
