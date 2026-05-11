# =============================================================================
# ml/algorithms/decision_tree.py
# Decision Tree classifier with hyperparameter configuration
# =============================================================================

from sklearn.tree import DecisionTreeClassifier
from config.config import RANDOM_SEED, MAX_DEPTH, MIN_SAMPLES_SPLIT


def build_decision_tree(
    max_depth: int = MAX_DEPTH,
    min_samples_split: int = MIN_SAMPLES_SPLIT,
    random_state: int = RANDOM_SEED,
    class_weight: str = "balanced",
    criterion: str = "gini"
) -> DecisionTreeClassifier:
    """
    Build and return a configured Decision Tree classifier.

    Args:
        max_depth         : Maximum depth of the tree
        min_samples_split : Minimum samples required to split a node
        random_state      : Random seed
        class_weight      : 'balanced' to handle class imbalance
        criterion         : 'gini' or 'entropy'

    Returns:
        Configured but unfitted DecisionTreeClassifier
    """
    return DecisionTreeClassifier(
        max_depth=max_depth,
        min_samples_split=min_samples_split,
        min_samples_leaf=2,
        criterion=criterion,
        splitter="best",
        class_weight=class_weight,
        random_state=random_state
    )


def get_hyperparameter_grid() -> dict:
    """Return hyperparameter grid for GridSearchCV."""
    return {
        "max_depth":         [5, 10, 20, None],
        "min_samples_split": [2, 5, 10],
        "criterion":         ["gini", "entropy"],
        "class_weight":      ["balanced", None]
    }
