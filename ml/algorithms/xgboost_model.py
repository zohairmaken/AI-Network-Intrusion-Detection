# =============================================================================
# ml/algorithms/xgboost_model.py
# XGBoost classifier with graceful fallback if xgboost not installed
# =============================================================================

from config.config import RANDOM_SEED, N_ESTIMATORS, N_JOBS

_xgb_available = False
try:
    from xgboost import XGBClassifier
    _xgb_available = True
except ImportError:
    pass


def is_available() -> bool:
    """Return True if xgboost is installed."""
    return _xgb_available


def build_xgboost(
    n_estimators: int = N_ESTIMATORS,
    max_depth: int = 6,
    learning_rate: float = 0.1,
    random_state: int = RANDOM_SEED,
    n_jobs: int = N_JOBS,
    use_label_encoder: bool = False
):
    """
    Build and return a configured XGBoost classifier.

    Returns None if xgboost is not installed.
    """
    if not _xgb_available:
        return None

    return XGBClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        learning_rate=learning_rate,
        subsample=0.8,
        colsample_bytree=0.8,
        gamma=0.1,
        reg_alpha=0.1,
        reg_lambda=1.0,
        use_label_encoder=use_label_encoder,
        eval_metric="mlogloss",
        random_state=random_state,
        n_jobs=n_jobs,
        verbosity=0
    )


def get_hyperparameter_grid() -> dict:
    return {
        "n_estimators":    [100, 200, 300],
        "max_depth":       [4, 6, 8],
        "learning_rate":   [0.05, 0.1, 0.2],
        "subsample":       [0.7, 0.8, 1.0],
        "colsample_bytree":[0.7, 0.8, 1.0]
    }
