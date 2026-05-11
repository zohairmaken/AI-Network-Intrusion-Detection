# =============================================================================
# app/app.py  —  Main Streamlit Application (AI-Powered NIDS Dashboard)
# =============================================================================

import os, sys, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import streamlit as st
import pandas as pd

# ── Page config (must be first Streamlit call) ────────────────────────────────
st.set_page_config(
    page_title="AI-NIDS | Network Intrusion Detection",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="expanded"
)

from app.authentication import is_session_valid, render_login_page, logout
from app.dashboard import (
    render_header, stat_card, threat_level_gauge,
    live_traffic_chart, attack_distribution_pie,
    severity_bar_chart, model_accuracy_bar, recent_alerts_table,
    packets_per_second_chart
)
from app.alert_system import get_alerts, get_alert_stats, clear_alerts
from app.utils import (
    get_system_stats, get_network_interfaces, get_local_ip,
    load_attack_logs_df, load_sample_traffic, format_bytes,
    format_duration, get_uptime_str
)
from core.traffic_monitor import (
    start_monitoring, stop_monitoring, get_traffic_stats,
    get_timeline_data, get_recent_alerts, get_recent_packets, is_monitoring
)
from core.intrusion_detector import initialize as init_detector, is_initialized, get_loaded_models
from ml.model_loader import models_exist
from config.paths import (
    CONFUSION_MATRIX_PATH, ACCURACY_GRAPH_PATH,
    ATTACK_DIST_PATH, FEATURE_IMPORTANCE_PATH, ROC_CURVE_PATH
)
from config.config import APP_NAME, APP_VERSION, DASHBOARD_REFRESH_INTERVAL

# ── Global CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');

*, html, body { font-family: 'Inter', sans-serif !important; }
.main, .block-container { background-color: #0a0e1a !important; color: #e2e8f0; }
[data-testid="stSidebar"] { background: #0d1421 !important; border-right: 1px solid #1e3a5f; }
[data-testid="stSidebar"] * { color: #e2e8f0 !important; }
.stButton > button {
    background: linear-gradient(135deg, #00aaff, #0066cc);
    color: white; border: none; border-radius: 8px;
    font-weight: 600; transition: all 0.2s;
}
.stButton > button:hover { transform: translateY(-1px); box-shadow: 0 4px 15px rgba(0,170,255,0.3); }
.stSelectbox > div, .stTextInput > div { background: #121929 !important; border-color: #1e3a5f !important; }
div[data-testid="metric-container"] { background:#121929; border-radius:10px; border:1px solid #1e3a5f; padding:12px; }
h1,h2,h3 { color: #e2e8f0 !important; }
.stDataFrame { background: #121929 !important; }
.stTabs [data-baseweb="tab-list"] { background: #0d1421; border-radius: 10px; }
.stTabs [data-baseweb="tab"] { color: #64748b !important; }
.stTabs [aria-selected="true"] { color: #00aaff !important; border-bottom: 2px solid #00aaff; }
hr { border-color: #1e3a5f; }
footer { visibility: hidden; }
</style>
""", unsafe_allow_html=True)

# ─── Auth gate ────────────────────────────────────────────────────────────────
if not is_session_valid():
    render_login_page()
    st.stop()

username = st.session_state.get("username", "admin")
role     = st.session_state.get("role", "Administrator")

# ─── Session state init ───────────────────────────────────────────────────────
if "model_results"    not in st.session_state: st.session_state["model_results"]    = {}
if "pps_history"      not in st.session_state: st.session_state["pps_history"]      = []
if "demo_mode"        not in st.session_state: st.session_state["demo_mode"]        = True
if "selected_model"   not in st.session_state: st.session_state["selected_model"]   = "random_forest"
if "auto_refresh"     not in st.session_state: st.session_state["auto_refresh"]     = True

# ─── Sidebar ──────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div style="text-align:center; padding:16px 0 8px;">
        <div style="font-size:2.5rem;">🛡</div>
        <div style="font-size:1rem; font-weight:800; color:#00aaff;">AI-NIDS</div>
        <div style="font-size:0.7rem; color:#64748b; margin-top:2px;">v""" + APP_VERSION + """</div>
    </div>
    <hr style="border-color:#1e3a5f; margin:8px 0 16px;">
    """, unsafe_allow_html=True)

    page = st.selectbox("📍 Navigation", [
        "🏠 Dashboard",
        "📡 Live Monitor",
        "🚨 Alerts",
        "🤖 ML Models",
        "📊 Analytics",
        "📋 Logs",
        "⚙️ Settings"
    ], label_visibility="collapsed")

    st.markdown("<hr style='border-color:#1e3a5f;'>", unsafe_allow_html=True)

    # Monitor controls
    st.markdown("**🎛 Monitor Controls**")
    col_s, col_x = st.columns(2)
    with col_s:
        if st.button("▶ Start", use_container_width=True, disabled=is_monitoring()):
            demo_rows = load_sample_traffic()
            if not is_initialized():
                try:
                    init_detector([st.session_state["selected_model"]])
                except Exception as e:
                    st.error(f"Model error: {e}")
                    st.stop()
            start_monitoring(
                model_name=st.session_state["selected_model"],
                demo_mode=st.session_state["demo_mode"],
                demo_rows=demo_rows
            )
            st.rerun()
    with col_x:
        if st.button("⏹ Stop", use_container_width=True, disabled=not is_monitoring()):
            stop_monitoring()
            st.rerun()

    status_color = "#00ff88" if is_monitoring() else "#ff4444"
    status_label = "● LIVE" if is_monitoring() else "● STOPPED"
    st.markdown(
        f'<div style="text-align:center; color:{status_color}; font-weight:700; '
        f'font-size:0.85rem; margin:8px 0;">{status_label}</div>',
        unsafe_allow_html=True
    )

    st.markdown("<hr style='border-color:#1e3a5f;'>", unsafe_allow_html=True)
    st.markdown("**⚙️ Options**")
    st.session_state["demo_mode"] = st.checkbox(
        "Demo Mode (no admin req.)", value=st.session_state["demo_mode"]
    )
    st.session_state["selected_model"] = st.selectbox(
        "ML Model", ["random_forest", "decision_tree", "xgboost"],
        index=0
    )
    st.session_state["auto_refresh"] = st.checkbox(
        "Auto-refresh dashboard", value=st.session_state["auto_refresh"]
    )

    st.markdown("<hr style='border-color:#1e3a5f;'>", unsafe_allow_html=True)
    sys_stats = get_system_stats()
    st.markdown("**💻 System**")
    st.caption(f"CPU: {sys_stats.get('cpu_percent',0):.0f}%")
    st.progress(int(sys_stats.get("cpu_percent", 0)) / 100)
    st.caption(f"RAM: {sys_stats.get('memory_percent',0):.0f}%")
    st.progress(int(sys_stats.get("memory_percent", 0)) / 100)
    st.caption(f"IP: {get_local_ip()}")

    st.markdown("<hr style='border-color:#1e3a5f;'>", unsafe_allow_html=True)
    if st.button("🚪 Logout", use_container_width=True):
        logout(); st.rerun()

# ─── Header ───────────────────────────────────────────────────────────────────
render_header(username=username, role=role)

# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: DASHBOARD
# ═══════════════════════════════════════════════════════════════════════════════
if page == "🏠 Dashboard":
    traffic = get_traffic_stats()
    timeline = get_timeline_data()
    alert_stats = get_alert_stats()
    alerts = get_alerts(10)

    total   = traffic.get("total_packets", 0)
    attacks = traffic.get("attack_packets", 0)
    normal  = traffic.get("normal_packets", 0)
    pps     = traffic.get("packets_per_sec", 0.0)
    risk    = (attacks / max(total, 1)) * 0.85 if attacks else 0.0

    # ── Top KPI row ────────────────────────────────────────────────────────────
    c1, c2, c3, c4, c5 = st.columns(5)
    with c1: stat_card("Total Packets",   f"{total:,}",   icon="📦", color="#00aaff")
    with c2: stat_card("Attacks Detected",f"{attacks:,}", icon="🚨", color="#ff4444")
    with c3: stat_card("Normal Traffic",  f"{normal:,}",  icon="✅", color="#00ff88")
    with c4: stat_card("Packets/sec",     f"{pps:.1f}",   icon="⚡", color="#ffdd00")
    with c5: stat_card("Total Alerts",    f"{alert_stats.get('total',0):,}", icon="🔔", color="#ff8800")

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Charts row ────────────────────────────────────────────────────────────
    col_left, col_mid, col_right = st.columns([2, 1.2, 1])
    with col_left:
        if timeline["labels"]:
            st.plotly_chart(
                live_traffic_chart(timeline["labels"], timeline["packets"], timeline["attacks"]),
                use_container_width=True
            )
        else:
            st.info("📡 Start monitoring to see live traffic chart.")

    with col_mid:
        st.plotly_chart(attack_distribution_pie(traffic), use_container_width=True)

    with col_right:
        st.plotly_chart(threat_level_gauge(risk), use_container_width=True)
        st.markdown("<br>", unsafe_allow_html=True)
        st.plotly_chart(severity_bar_chart(alert_stats), use_container_width=True)

    # ── Recent alerts table ────────────────────────────────────────────────────
    st.markdown("### 🚨 Recent Alerts")
    recent_alerts_table(alerts)

    if st.session_state["auto_refresh"] and is_monitoring():
        time.sleep(DASHBOARD_REFRESH_INTERVAL)
        st.rerun()

# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: LIVE MONITOR
# ═══════════════════════════════════════════════════════════════════════════════
elif page == "📡 Live Monitor":
    st.markdown("## 📡 Live Network Monitor")
    traffic = get_traffic_stats()

    col1, col2, col3 = st.columns(3)
    with col1: stat_card("Status", "LIVE" if is_monitoring() else "STOPPED",
                         color="#00ff88" if is_monitoring() else "#ff4444", icon="🔴")
    with col2: stat_card("Uptime",
                         get_uptime_str(traffic.get("start_time")), icon="⏱")
    with col3: stat_card("Model", traffic.get("model_used","N/A").replace("_"," ").title(), icon="🤖")

    st.markdown("<br>", unsafe_allow_html=True)

    # Live packet feed
    st.markdown("### 📊 Live Packet Feed")
    pkts = get_recent_packets(30)
    if pkts:
        df_pkts = pd.DataFrame(pkts)
        def color_pred(val):
            from config.config import SEVERITY_COLORS
            color = SEVERITY_COLORS.get(val, "#ffffff")
            return f"color: {color}; font-weight: 600"
        st.dataframe(
            df_pkts.style.applymap(color_pred, subset=["prediction"]),
            use_container_width=True, height=400
        )
    else:
        st.info("No packets captured yet. Start monitoring.")

    if st.session_state["auto_refresh"] and is_monitoring():
        time.sleep(2); st.rerun()

# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: ALERTS
# ═══════════════════════════════════════════════════════════════════════════════
elif page == "🚨 Alerts":
    st.markdown("## 🚨 Alert Management")
    alert_stats = get_alert_stats()

    c1, c2, c3, c4 = st.columns(4)
    with c1: stat_card("Total",    str(alert_stats.get("total",0)),    icon="🔔", color="#00aaff")
    with c2: stat_card("Critical", str(alert_stats.get("critical",0)), icon="🔴", color="#ff2266")
    with c3: stat_card("High",     str(alert_stats.get("high",0)),     icon="🟠", color="#ff4444")
    with c4: stat_card("Medium",   str(alert_stats.get("medium",0)),   icon="🟡", color="#ff8800")

    st.markdown("<br>", unsafe_allow_html=True)
    sev_filter = st.selectbox("Filter by severity", ["All","CRITICAL","HIGH","MEDIUM","LOW"])
    alerts = get_alerts(50, severity_filter=None if sev_filter=="All" else sev_filter)
    recent_alerts_table(alerts)

    if st.button("🗑 Clear All Alerts"):
        clear_alerts(); st.rerun()

# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: ML MODELS
# ═══════════════════════════════════════════════════════════════════════════════
elif page == "🤖 ML Models":
    st.markdown("## 🤖 Machine Learning Models")

    tab1, tab2, tab3 = st.tabs(["🏋 Train Models", "📈 Performance", "🖼 Visualizations"])

    with tab1:
        st.markdown("### Train / Retrain All Models")
        dataset_choice = st.selectbox("Dataset", ["synthetic","cicids","nslkdd"])
        col_t, col_s = st.columns([1, 3])
        with col_t:
            if st.button("🚀 Start Training", use_container_width=True):
                with st.spinner("Training models — this may take 1-2 minutes..."):
                    try:
                        from ml.train_model import train_and_evaluate
                        results = train_and_evaluate(prefer_dataset=dataset_choice)
                        st.session_state["model_results"] = results
                        st.success("✅ All models trained and saved!")
                        for name, m in results.items():
                            st.info(f"**{name}** — Accuracy: {m['accuracy']:.2f}%  F1: {m['f1_score']:.2f}%")
                    except Exception as e:
                        st.error(f"Training failed: {e}")

        exist = models_exist()
        st.markdown("**Model Files:**")
        for name, ok in exist.items():
            icon = "✅" if ok else "❌"
            st.markdown(f"{icon} `{name}`")

    with tab2:
        results = st.session_state.get("model_results", {})
        if results:
            st.plotly_chart(model_accuracy_bar(results), use_container_width=True)
            for name, m in results.items():
                with st.expander(f"📋 {name.replace('_',' ').title()} — Detailed Report"):
                    c1,c2,c3,c4 = st.columns(4)
                    c1.metric("Accuracy",  f"{m['accuracy']:.2f}%")
                    c2.metric("Precision", f"{m['precision']:.2f}%")
                    c3.metric("Recall",    f"{m['recall']:.2f}%")
                    c4.metric("F1-Score",  f"{m['f1_score']:.2f}%")
        else:
            st.info("Train models first to see performance metrics.")

    with tab3:
        viz_paths = {
            "Confusion Matrix":   CONFUSION_MATRIX_PATH,
            "Accuracy Comparison":ACCURACY_GRAPH_PATH,
            "Attack Distribution":ATTACK_DIST_PATH,
            "Feature Importance": FEATURE_IMPORTANCE_PATH,
            "ROC Curves":         ROC_CURVE_PATH
        }
        cols = st.columns(2)
        for i, (title, path) in enumerate(viz_paths.items()):
            with cols[i % 2]:
                if os.path.exists(path):
                    st.markdown(f"**{title}**")
                    st.image(path, use_column_width=True)
                else:
                    st.info(f"{title}: Train models first.")

# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: ANALYTICS
# ═══════════════════════════════════════════════════════════════════════════════
elif page == "📊 Analytics":
    st.markdown("## 📊 Traffic Analytics")
    df = load_attack_logs_df()
    if df.empty:
        st.info("No attack logs yet. Start monitoring to collect data.")
    else:
        tab1, tab2 = st.tabs(["📈 Charts", "🗂 Raw Data"])
        with tab1:
            import plotly.express as px
            if "prediction" in df.columns:
                counts = df["prediction"].value_counts().reset_index()
                counts.columns = ["Attack Type","Count"]
                fig = px.bar(counts, x="Attack Type", y="Count",
                             color="Attack Type",
                             color_discrete_map={
                                 "NORMAL":"#00ff88","DoS Attack":"#ff4444",
                                 "Port Scan":"#ff8800","Brute Force":"#ff2266",
                                 "Suspicious Activity":"#ffdd00"
                             })
                fig.update_layout(paper_bgcolor="#0a0e1a", plot_bgcolor="#121929",
                                  font_color="#e2e8f0")
                st.plotly_chart(fig, use_container_width=True)

            if "severity" in df.columns:
                sev_counts = df["severity"].value_counts().reset_index()
                sev_counts.columns = ["Severity","Count"]
                fig2 = px.pie(sev_counts, names="Severity", values="Count",
                              color_discrete_sequence=["#ff2266","#ff4444","#ff8800","#ffdd00"])
                fig2.update_layout(paper_bgcolor="#0a0e1a", font_color="#e2e8f0")
                st.plotly_chart(fig2, use_container_width=True)

        with tab2:
            st.dataframe(df, use_container_width=True, height=500)
            csv = df.to_csv(index=False).encode()
            st.download_button("⬇ Download CSV", csv, "attack_logs.csv", "text/csv")

# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: LOGS
# ═══════════════════════════════════════════════════════════════════════════════
elif page == "📋 Logs":
    st.markdown("## 📋 System Logs")
    df = load_attack_logs_df()
    if df.empty:
        st.info("No logs found.")
    else:
        st.metric("Total Log Entries", len(df))
        st.dataframe(df.tail(200), use_container_width=True, height=500)
        col1, col2 = st.columns(2)
        with col1:
            st.download_button("⬇ Download CSV", df.to_csv(index=False).encode(),
                               "attack_logs.csv", "text/csv", use_container_width=True)
        with col2:
            st.download_button("⬇ Download JSON",
                               df.to_json(orient="records", indent=2).encode(),
                               "attack_logs.json", "application/json", use_container_width=True)

# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: SETTINGS
# ═══════════════════════════════════════════════════════════════════════════════
elif page == "⚙️ Settings":
    st.markdown("## ⚙️ System Settings")
    tab1, tab2, tab3 = st.tabs(["🌐 Network", "📧 Email Alerts", "ℹ️ About"])

    with tab1:
        st.markdown("### Network Interfaces")
        ifaces = get_network_interfaces()
        if ifaces:
            st.dataframe(pd.DataFrame(ifaces), use_container_width=True)
        else:
            st.info("Could not enumerate interfaces.")
        st.markdown("### System Stats")
        sys_stats = get_system_stats()
        c1,c2,c3 = st.columns(3)
        c1.metric("CPU", f"{sys_stats.get('cpu_percent',0):.1f}%")
        c2.metric("RAM", f"{sys_stats.get('memory_percent',0):.1f}%")
        c3.metric("Disk",f"{sys_stats.get('disk_percent',0):.1f}%")

    with tab2:
        st.markdown("### Email Alert Configuration")
        st.info("Set EMAIL_ALERTS_ENABLED=True in config/config.py and provide SMTP credentials.")
        st.code("""
EMAIL_ALERTS_ENABLED = True
SMTP_SERVER   = 'smtp.gmail.com'
SMTP_PORT     = 587
SENDER_EMAIL  = 'your@gmail.com'
RECEIVER_EMAIL= 'admin@example.com'
EMAIL_APP_PASSWORD = 'your-app-password'
        """)

    with tab3:
        st.markdown(f"""
        ### {APP_NAME}
        **Version:** {APP_VERSION}

        **Tech Stack:**
        - 🐍 Python 3.10+
        - 🎈 Streamlit Dashboard
        - 🤖 Random Forest / Decision Tree / XGBoost
        - 📡 Scapy Packet Sniffer
        - 📊 Plotly Interactive Charts

        **Accuracy:** >95% on synthetic dataset

        **Default Login:** admin / nids@2024
        """)
