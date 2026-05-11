# =============================================================================
# ml/evaluate_model.py
# Model evaluation: metrics, confusion matrix, ROC curves, comparison
# =============================================================================

import os
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_curve, auc
)
from sklearn.preprocessing import label_binarize

from config.paths import (
    CONFUSION_MATRIX_PATH, ACCURACY_GRAPH_PATH,
    ATTACK_DIST_PATH, ROC_CURVE_PATH, VIZ_DIR
)
from config.constants import ALL_CLASSES
import core.logger as log

# ─── Dark theme palette ───────────────────────────────────────────────────────
BG_COLOR    = "#0a0e1a"
CARD_COLOR  = "#121929"
ACCENT      = "#00aaff"
TEXT_COLOR  = "white"
GRID_COLOR  = "#1e2d40"


def _apply_dark_style(fig, ax_or_axes):
    """Apply consistent dark cybersecurity theme to matplotlib figures."""
    fig.patch.set_facecolor(BG_COLOR)
    axes = ax_or_axes if isinstance(ax_or_axes, (list, np.ndarray)) else [ax_or_axes]
    for ax in np.array(axes).flatten():
        ax.set_facecolor(CARD_COLOR)
        ax.tick_params(colors=TEXT_COLOR, labelsize=9)
        ax.xaxis.label.set_color(TEXT_COLOR)
        ax.yaxis.label.set_color(TEXT_COLOR)
        ax.title.set_color(TEXT_COLOR)
        for spine in ax.spines.values():
            spine.set_color(GRID_COLOR)
        ax.grid(color=GRID_COLOR, linewidth=0.5, alpha=0.5)


def compute_metrics(y_true: np.ndarray, y_pred: np.ndarray, class_names: list = None) -> dict:
    """
    Compute comprehensive evaluation metrics.

    Returns:
        Dict with accuracy, precision, recall, f1, per-class report
    """
    if class_names is None:
        class_names = ALL_CLASSES

    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, average="weighted", zero_division=0)
    rec  = recall_score(y_true, y_pred, average="weighted", zero_division=0)
    f1   = f1_score(y_true, y_pred, average="weighted", zero_division=0)

    # Per-class report
    report = classification_report(
        y_true, y_pred,
        target_names=class_names[:len(np.unique(y_true))],
        output_dict=True,
        zero_division=0
    )

    metrics = {
        "accuracy":  round(acc * 100, 2),
        "precision": round(prec * 100, 2),
        "recall":    round(rec * 100, 2),
        "f1_score":  round(f1 * 100, 2),
        "report":    report
    }

    log.info(
        "Model Evaluation → Acc: %.2f%% | Prec: %.2f%% | Rec: %.2f%% | F1: %.2f%%",
        metrics["accuracy"], metrics["precision"], metrics["recall"], metrics["f1_score"]
    )
    return metrics


def plot_confusion_matrix(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    class_names: list = None,
    save_path: str = CONFUSION_MATRIX_PATH
) -> str:
    """Plot and save a styled confusion matrix heatmap."""
    if class_names is None:
        class_names = ALL_CLASSES

    # Map numeric labels back to names if needed
    unique_labels = sorted(np.unique(np.concatenate([y_true, y_pred])))
    if len(unique_labels) < len(class_names):
        display_names = [class_names[i] for i in unique_labels]
    else:
        display_names = class_names[:len(unique_labels)]

    cm = confusion_matrix(y_true, y_pred, labels=unique_labels)
    cm_normalized = cm.astype("float") / cm.sum(axis=1, keepdims=True)

    fig, ax = plt.subplots(figsize=(9, 7))
    _apply_dark_style(fig, ax)

    sns.heatmap(
        cm_normalized, annot=cm, fmt="d",
        cmap="Blues", linewidths=0.5, linecolor=GRID_COLOR,
        xticklabels=display_names, yticklabels=display_names,
        ax=ax, cbar_kws={"shrink": 0.8}
    )
    ax.set_xlabel("Predicted Label", fontsize=11)
    ax.set_ylabel("True Label", fontsize=11)
    ax.set_title("Confusion Matrix — NIDS Classification", fontsize=14, fontweight="bold", pad=15)
    plt.xticks(rotation=30, ha="right")
    plt.yticks(rotation=0)
    plt.tight_layout()
    os.makedirs(VIZ_DIR, exist_ok=True)
    plt.savefig(save_path, dpi=150, bbox_inches="tight", facecolor=BG_COLOR)
    plt.close()
    log.info("Confusion matrix saved → %s", save_path)
    return save_path


def plot_accuracy_comparison(
    results: dict,
    save_path: str = ACCURACY_GRAPH_PATH
) -> str:
    """
    Bar chart comparing multiple model accuracies.

    Args:
        results: dict mapping model_name -> metrics_dict
        save_path: output PNG path
    """
    models  = list(results.keys())
    metrics = ["accuracy", "precision", "recall", "f1_score"]
    labels  = ["Accuracy", "Precision", "Recall", "F1-Score"]
    colors  = ["#00aaff", "#00ff88", "#ffdd00", "#ff8800"]

    x = np.arange(len(models))
    width = 0.2
    fig, ax = plt.subplots(figsize=(10, 6))
    _apply_dark_style(fig, ax)

    for i, (metric, label, color) in enumerate(zip(metrics, labels, colors)):
        vals = [results[m].get(metric, 0) for m in models]
        bars = ax.bar(x + i * width, vals, width, label=label, color=color, alpha=0.85)
        for bar in bars:
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 0.5,
                f"{bar.get_height():.1f}%",
                ha="center", va="bottom", color=TEXT_COLOR, fontsize=8
            )

    ax.set_xlabel("Model", fontsize=11)
    ax.set_ylabel("Score (%)", fontsize=11)
    ax.set_title("Model Performance Comparison", fontsize=14, fontweight="bold")
    ax.set_xticks(x + width * 1.5)
    ax.set_xticklabels(models, fontsize=10)
    ax.set_ylim(0, 110)
    ax.legend(facecolor=CARD_COLOR, edgecolor=GRID_COLOR, labelcolor=TEXT_COLOR)
    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches="tight", facecolor=BG_COLOR)
    plt.close()
    log.info("Accuracy comparison chart saved → %s", save_path)
    return save_path


def plot_attack_distribution(
    y: np.ndarray,
    class_names: list = None,
    save_path: str = ATTACK_DIST_PATH
) -> str:
    """Pie + bar chart showing attack class distribution."""
    if class_names is None:
        class_names = ALL_CLASSES

    from collections import Counter
    counts = Counter(y)
    labels_idx = sorted(counts.keys())
    names  = [class_names[i] if i < len(class_names) else str(i) for i in labels_idx]
    sizes  = [counts[i] for i in labels_idx]
    colors = ["#00ff88", "#ff4444", "#ff8800", "#ff2266", "#ffdd00"][:len(names)]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 6))
    _apply_dark_style(fig, [ax1, ax2])
    fig.suptitle("Traffic Class Distribution", color=TEXT_COLOR, fontsize=14, fontweight="bold")

    # Pie
    wedges, texts, autotexts = ax1.pie(
        sizes, labels=names, colors=colors,
        autopct="%1.1f%%", startangle=140,
        wedgeprops={"edgecolor": BG_COLOR, "linewidth": 2}
    )
    for t in texts + autotexts:
        t.set_color(TEXT_COLOR)
    ax1.set_title("Proportion", color=TEXT_COLOR)

    # Bar
    bars = ax2.bar(names, sizes, color=colors, edgecolor=BG_COLOR, linewidth=1.5)
    for bar, size in zip(bars, sizes):
        ax2.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + max(sizes) * 0.01,
            f"{size:,}", ha="center", va="bottom", color=TEXT_COLOR, fontsize=9
        )
    ax2.set_xlabel("Class", fontsize=10)
    ax2.set_ylabel("Sample Count", fontsize=10)
    ax2.set_title("Sample Counts", color=TEXT_COLOR)
    plt.xticks(rotation=20, ha="right")
    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches="tight", facecolor=BG_COLOR)
    plt.close()
    log.info("Attack distribution chart saved → %s", save_path)
    return save_path


def plot_roc_curves(
    model,
    X_test: np.ndarray,
    y_test: np.ndarray,
    class_names: list = None,
    save_path: str = ROC_CURVE_PATH
) -> str:
    """Plot One-vs-Rest ROC curves for all classes."""
    if class_names is None:
        class_names = ALL_CLASSES

    n_classes = len(np.unique(y_test))
    y_bin = label_binarize(y_test, classes=list(range(n_classes)))

    if not hasattr(model, "predict_proba"):
        log.warning("Model lacks predict_proba; skipping ROC curves.")
        return ""

    y_score = model.predict_proba(X_test)
    colors_roc = plt.cm.tab10(np.linspace(0, 1, n_classes))

    fig, ax = plt.subplots(figsize=(9, 7))
    _apply_dark_style(fig, ax)

    for i in range(min(n_classes, len(class_names))):
        if y_bin.shape[1] <= i:
            break
        fpr, tpr, _ = roc_curve(y_bin[:, i], y_score[:, i])
        roc_auc = auc(fpr, tpr)
        ax.plot(fpr, tpr, color=colors_roc[i], linewidth=2,
                label=f"{class_names[i]} (AUC = {roc_auc:.3f})")

    ax.plot([0, 1], [0, 1], "w--", linewidth=1, alpha=0.5, label="Random Classifier")
    ax.set_xlabel("False Positive Rate", fontsize=11)
    ax.set_ylabel("True Positive Rate", fontsize=11)
    ax.set_title("ROC Curves — Multi-Class OvR", fontsize=14, fontweight="bold")
    ax.legend(facecolor=CARD_COLOR, edgecolor=GRID_COLOR, labelcolor=TEXT_COLOR, fontsize=9)
    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches="tight", facecolor=BG_COLOR)
    plt.close()
    log.info("ROC curves saved → %s", save_path)
    return save_path
