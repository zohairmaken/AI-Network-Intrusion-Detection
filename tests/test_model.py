# =============================================================================
# tests/test_model.py
# Unit tests for ML model training, loading, and prediction
# =============================================================================

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier

from ml.algorithms.random_forest import build_random_forest
from ml.algorithms.decision_tree import build_decision_tree
from ml.preprocess import generate_synthetic_dataset, clean_data, encode_labels
from config.constants import FEATURE_COLUMNS, ALL_CLASSES


class TestModelBuilders(unittest.TestCase):

    def test_random_forest_type(self):
        model = build_random_forest(n_estimators=10)
        self.assertIsInstance(model, RandomForestClassifier)

    def test_decision_tree_type(self):
        model = build_decision_tree()
        self.assertIsInstance(model, DecisionTreeClassifier)

    def test_random_forest_trains(self):
        model = build_random_forest(n_estimators=5, max_depth=3)
        X = np.random.rand(100, len(FEATURE_COLUMNS))
        y = np.random.randint(0, 5, 100)
        model.fit(X, y)
        preds = model.predict(X)
        self.assertEqual(len(preds), 100)

    def test_decision_tree_trains(self):
        model = build_decision_tree(max_depth=3)
        X = np.random.rand(100, len(FEATURE_COLUMNS))
        y = np.random.randint(0, 5, 100)
        model.fit(X, y)
        preds = model.predict(X)
        self.assertEqual(len(preds), 100)

    def test_predict_proba_available(self):
        model = build_random_forest(n_estimators=5, max_depth=3)
        X = np.random.rand(50, len(FEATURE_COLUMNS))
        y = np.random.randint(0, 5, 50)
        model.fit(X, y)
        proba = model.predict_proba(X[:5])
        self.assertEqual(proba.shape[0], 5)


class TestPreprocessing(unittest.TestCase):

    def test_synthetic_dataset_shape(self):
        df = generate_synthetic_dataset(n_samples=500)
        self.assertGreater(len(df), 400)
        self.assertIn("label", df.columns)

    def test_synthetic_has_all_classes(self):
        df = generate_synthetic_dataset(n_samples=1000)
        labels = df["label"].unique()
        for cls in ALL_CLASSES:
            self.assertIn(cls, labels)

    def test_clean_data_no_inf(self):
        import pandas as pd
        import numpy as np
        df = generate_synthetic_dataset(500)
        df.loc[0, "flow_rate"] = np.inf
        df.loc[1, "pkt_length"] = -np.inf
        cleaned = clean_data(df)
        num_cols = cleaned.select_dtypes(include=np.number).columns
        self.assertFalse(cleaned[num_cols].isin([np.inf, -np.inf]).any().any())

    def test_encode_labels_returns_integers(self):
        df = generate_synthetic_dataset(200)
        df_clean = clean_data(df)
        df_enc, le = encode_labels(df_clean)
        self.assertIn("label_encoded", df_enc.columns)
        self.assertTrue(df_enc["label_encoded"].dtype in [int, "int64", "int32"])

    def test_feature_columns_present(self):
        df = generate_synthetic_dataset(200)
        for col in FEATURE_COLUMNS:
            self.assertIn(col, df.columns, f"Missing column: {col}")


if __name__ == "__main__":
    unittest.main()
