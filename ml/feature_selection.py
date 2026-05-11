# =============================================================================
# ml/feature_selection.py
# Feature importance analysis and selection utilities
# =============================================================================

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.feature_selection import (
    SelectKBest, f_classif, mutual_info_classif, RFE
)

from config.paths import FEATURE_IMPORTANCE_PATH
from config.constants import FEATURE_COLUMNS
import core.logger as log


def compute_feature_importance(model, feature_names: list = None) -> pd.DataFrame:
    """
    Extract feature importances from a tree-based model.

    Args:
        model        : Trained RandomForest / DecisionTree / XGBoost model
        feature_names: Column names (uses FEATURE_COLUMNS if None)

    Returns:
        DataFrame with 'feature' and 'importance' columns, sorted descending
    """
    if feature_names is None:
        feature_names = FEATURE_COLUMNS

    if not hasattr(model, "feature_importances_"):
        log.warning("Model does not expose feature_importances_.")
        return pd.DataFrame({"feature": feature_names, "importance": [0.0] * len(feature_names)})

    importances = model.feature_importances_
    df = pd.DataFrame({
        "feature":    feature_names[:len(importances)],
        "importance": importances
    }).sort_values("importance", ascending=False).reset_index(drop=True)
    return df


def plot_feature_importance(
    model,
    feature_names: list = None,
    top_n: int = 15,
    save_path: str = FEATURE_IMPORTANCE_PATH
) -> str:
    """
    Plot a horizontal bar chart of top-N feature importances.

    Returns:
        Path to saved PNG
    """
    df = compute_feature_importance(model, feature_names)
    df = df.head(top_n)

    fig, ax = plt.subplots(figsize=(10, 6))
    fig.patch.set_facecolor("#0a0e1a")
    ax.set_facecolor("#121929")

    colors = plt.cm.plasma(np.linspace(0.2, 0.9, len(df)))
    bars = ax.barh(df["feature"][::-1], df["importance"][::-1], color=colors[::-1])

    ax.set_xlabel("Importance Score", color="white", fontsize=11)
    ax.set_title(f"Top {top_n} Feature Importances", color="white", fontsize=14, fontweight="bold")
    ax.tick_params(colors="white")
    ax.spines["bottom"].set_color("#334155")
    ax.spines["left"].set_color("#334155")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    for spine in ["top", "right"]:
        ax.spines[spine].set_visible(False)

    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close()
    log.info("Feature importance plot saved → %s", save_path)
    return save_path


def select_k_best_features(
    X: np.ndarray,
    y: np.ndarray,
    k: int = 15,
    feature_names: list = None
) -> tuple:
    """
    Select top-K features using ANOVA F-test.

    Returns:
        (X_selected, selected_feature_names, selector)
    """
    if feature_names is None:
        feature_names = FEATURE_COLUMNS

    selector = SelectKBest(score_func=f_classif, k=min(k, X.shape[1]))
    X_selected = selector.fit_transform(X, y)
    mask = selector.get_support()
    selected_names = [feature_names[i] for i in range(len(feature_names)) if mask[i]]
    log.info("Selected %d features via SelectKBest: %s", len(selected_names), selected_names)
    return X_selected, selected_names, selector


def select_mutual_info_features(
    X: np.ndarray,
    y: np.ndarray,
    threshold: float = 0.05,
    feature_names: list = None
) -> tuple:
    """
    Select features with mutual information above a threshold.

    Returns:
        (X_selected, selected_feature_names, mi_scores)
    """
    if feature_names is None:
        feature_names = FEATURE_COLUMNS

    mi_scores = mutual_info_classif(X, y, random_state=42)
    mask = mi_scores >= threshold
    X_selected = X[:, mask]
    selected_names = [feature_names[i] for i in range(len(feature_names)) if mask[i]]
    log.info(
        "Mutual info feature selection: %d/%d features kept (threshold=%.3f)",
        len(selected_names), len(feature_names), threshold
    )
    return X_selected, selected_names, mi_scores
