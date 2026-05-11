# =============================================================================
# ml/algorithms/random_forest.py
# Random Forest classifier with hyperparameter configuration
# =============================================================================

from sklearn.ensemble import RandomForestClassifier
from config.config import RANDOM_SEED, N_ESTIMATORS, MAX_DEPTH, MIN_SAMPLES_SPLIT, N_JOBS


def build_random_forest(
    n_estimators: int = N_ESTIMATORS,
    max_depth: int = MAX_DEPTH,
    min_samples_split: int = MIN_SAMPLES_SPLIT,
    random_state: int = RANDOM_SEED,
    n_jobs: int = N_JOBS,
    class_weight: str = "balanced"
) -> RandomForestClassifier:
    """
    Build and return a configured Random Forest classifier.

    Args:
        n_estimators      : Number of decision trees
        max_depth         : Maximum tree depth (None = unlimited)
        min_samples_split : Minimum samples to split an internal node
        random_state      : Random seed for reproducibility
        n_jobs            : CPU cores to use (-1 = all)
        class_weight      : Handle class imbalance ('balanced' recommended)

    Returns:
        Configured but unfitted RandomForestClassifier
    """
    return RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        min_samples_split=min_samples_split,
        min_samples_leaf=2,
        max_features="sqrt",
        bootstrap=True,
        oob_score=True,
        random_state=random_state,
        n_jobs=n_jobs,
        class_weight=class_weight,
        verbose=0
    )


def get_hyperparameter_grid() -> dict:
    """Return hyperparameter grid for GridSearchCV / RandomizedSearchCV."""
    return {
        "n_estimators":    [100, 200, 300],
        "max_depth":       [10, 20, None],
        "min_samples_split": [2, 5, 10],
        "max_features":    ["sqrt", "log2"],
        "class_weight":    ["balanced", None]
    }
