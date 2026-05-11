# =============================================================================
# run.py  —  Main project entry point
# =============================================================================
"""
AI-Powered Network Intrusion Detection System
=============================================
Usage:
    python run.py                  # Launch dashboard (default)
    python run.py --train          # Train ML models first, then launch
    python run.py --train-only     # Train models only, no dashboard
    python run.py --dataset cicids # Use CICIDS2017 dataset
"""

import os
import sys
import argparse
import subprocess

# ── Ensure project root is on PYTHONPATH ─────────────────────────────────────
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from config.paths import ensure_dirs
from ml.model_loader import models_exist
import core.logger as log


def train_models(dataset: str = "synthetic"):
    """Train all ML models."""
    log.info("Starting model training pipeline (dataset=%s)...", dataset)
    from ml.train_model import train_and_evaluate
    results = train_and_evaluate(prefer_dataset=dataset)
    return results


def launch_dashboard():
    """Launch the Streamlit dashboard."""
    app_path = os.path.join(ROOT, "app", "app.py")
    log.info("Launching Streamlit dashboard: %s", app_path)
    cmd = [
        sys.executable, "-m", "streamlit", "run", app_path,
        "--server.port", "8501",
        "--server.headless", "false",
        "--theme.base", "dark",
        "--theme.backgroundColor", "#0a0e1a",
        "--theme.primaryColor", "#00aaff",
        "--theme.textColor", "#e2e8f0"
    ]
    subprocess.run(cmd)


def main():
    parser = argparse.ArgumentParser(
        description="AI-Powered Network Intrusion Detection System"
    )
    parser.add_argument("--train",      action="store_true",
                        help="Train ML models before launching dashboard")
    parser.add_argument("--train-only", action="store_true",
                        help="Train models only (no dashboard)")
    parser.add_argument("--dataset",    default="synthetic",
                        choices=["synthetic", "cicids", "nslkdd"],
                        help="Dataset to use for training")
    args = parser.parse_args()

    # ── Ensure directories ────────────────────────────────────────────────────
    ensure_dirs()
    log.info("=" * 55)
    log.info("  AI-Powered Network Intrusion Detection System")
    log.info("=" * 55)

    # ── Training ──────────────────────────────────────────────────────────────
    if args.train or args.train_only:
        train_models(dataset=args.dataset)
        if args.train_only:
            log.info("Training complete. Exiting (--train-only).")
            return
    else:
        # Auto-train if no models exist
        existing = models_exist()
        if not any(existing.values()):
            log.info("No trained models found. Running training pipeline first...")
            train_models(dataset=args.dataset)
        else:
            trained = [k for k, v in existing.items() if v]
            log.info("Found trained models: %s", trained)

    # ── Dashboard ─────────────────────────────────────────────────────────────
    launch_dashboard()


if __name__ == "__main__":
    main()
