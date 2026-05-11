# =============================================================================
# ml/train_model.py
# Complete ML training pipeline — train, evaluate, and save all models
# =============================================================================

import os
import sys
import time
import joblib
import numpy as np

# ─── Path bootstrap so this script can be run directly ───────────────────────
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml.preprocess import preprocess_pipeline
from ml.evaluate_model import (
    compute_metrics, plot_confusion_matrix,
    plot_accuracy_comparison, plot_attack_distribution, plot_roc_curves
)
from ml.feature_selection import plot_feature_importance
from ml.algorithms.random_forest import build_random_forest
from ml.algorithms.decision_tree import build_decision_tree
from ml.algorithms.xgboost_model import build_xgboost, is_available as xgb_available
from ml.model_loader import save_model
from config.paths import ensure_dirs, VIZ_DIR
import core.logger as log


def train_and_evaluate(prefer_dataset: str = "synthetic") -> dict:
    """
    Full training pipeline:
      1. Preprocess data
      2. Train Random Forest, Decision Tree (+ XGBoost if available)
      3. Evaluate each model
      4. Save models and all visualizations
      5. Return comparison metrics dict

    Args:
        prefer_dataset: 'synthetic', 'cicids', or 'nslkdd'

    Returns:
        Dict mapping model_name -> metrics_dict
    """
    ensure_dirs()
    log.info("=" * 60)
    log.info("NIDS Model Training Pipeline Starting...")
    log.info("=" * 60)

    # ── Step 1: Preprocess ─────────────────────────────────────────────────────
    t0 = time.time()
    data = preprocess_pipeline(prefer=prefer_dataset)
    X_train = data["X_train"]
    X_test  = data["X_test"]
    y_train = data["y_train"]
    y_test  = data["y_test"]
    class_names = data["class_names"]
    feature_names = data["feature_names"]

    log.info(
        "Data ready | Train: %d | Test: %d | Classes: %s",
        len(X_train), len(X_test), class_names
    )

    # ── Step 2: Attack distribution visualization ─────────────────────────────
    plot_attack_distribution(
        np.concatenate([y_train, y_test]),
        class_names=class_names
    )

    # ── Step 3: Train models ───────────────────────────────────────────────────
    models_to_train = {
        "random_forest": build_random_forest(),
        "decision_tree": build_decision_tree()
    }
    if xgb_available():
        xgb = build_xgboost()
        if xgb is not None:
            models_to_train["xgboost"] = xgb

    results = {}

    for model_name, model in models_to_train.items():
        log.info("Training %s...", model_name)
        t_start = time.time()
        model.fit(X_train, y_train)
        t_end = time.time()
        log.info("%s trained in %.2f seconds.", model_name, t_end - t_start)

        # Evaluate
        y_pred = model.predict(X_test)
        metrics = compute_metrics(y_pred=y_pred, y_true=y_test, class_names=class_names)
        metrics["train_time_sec"] = round(t_end - t_start, 2)
        results[model_name] = metrics

        log.info(
            "[%s] Acc=%.2f%% | Prec=%.2f%% | Rec=%.2f%% | F1=%.2f%%",
            model_name.upper(),
            metrics["accuracy"], metrics["precision"],
            metrics["recall"], metrics["f1_score"]
        )

        # Save model
        save_model(model, model_name)

        # Per-model visualizations
        if model_name == "random_forest":
            plot_confusion_matrix(y_test, y_pred, class_names=class_names)
            plot_roc_curves(model, X_test, y_test, class_names=class_names)
            plot_feature_importance(model, feature_names=feature_names)

    # ── Step 4: Multi-model comparison chart ──────────────────────────────────
    plot_accuracy_comparison(results)

    # ── Summary ───────────────────────────────────────────────────────────────
    total_time = time.time() - t0
    log.info("=" * 60)
    log.info("Training complete in %.1f seconds.", total_time)
    log.info("=" * 60)
    for name, m in results.items():
        log.info("  %-18s → Accuracy: %.2f%%  F1: %.2f%%", name, m["accuracy"], m["f1_score"])
    log.info("=" * 60)

    return results


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="NIDS Model Training")
    parser.add_argument(
        "--dataset", choices=["synthetic", "cicids", "nslkdd"],
        default="synthetic",
        help="Dataset to train on (default: synthetic)"
    )
    args = parser.parse_args()
    train_and_evaluate(prefer_dataset=args.dataset)
