"""
Module: anomaly_detector.py
Author: IBM SkillsBuild Cyber Security Team / BharatCares Project
Date: October 2026
Purpose: Unsupervised zero-day network anomaly detector powered by Isolation Forest.
"""

import numpy as np
from sklearn.ensemble import IsolationForest
import joblib
from typing import Dict, Any

class ZeroDayAnomalyDetector:
    """
    Unsupervised Anomaly Detector using Isolation Forest to identify anomalous network behavior
    without requiring pre-existing signature definitions.
    """

    def __init__(self, contamination: float = 0.45, random_state: int = 42):
        """
        Initializes the Isolation Forest anomaly detector.

        Args:
            contamination (float): Expected proportion of outliers in the data.
            random_state (int): Random seed for reproducibility.
        """
        self.model = IsolationForest(
            n_estimators=120,
            contamination=contamination,
            random_state=random_state,
            n_jobs=-1
        )
        self.is_fitted = False

    def fit(self, X: np.ndarray) -> "ZeroDayAnomalyDetector":
        """Fits the Isolation Forest on feature matrix."""
        self.model.fit(X)
        self.is_fitted = True
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Predicts whether samples are anomalies (-1: anomaly/threat, 1: normal).

        Returns:
            np.ndarray: Binary anomaly indicator (1 = Anomaly, 0 = Normal).
        """
        raw_preds = self.model.predict(X)
        # Convert -1 (anomaly) -> 1, 1 (normal) -> 0
        return np.where(raw_preds == -1, 1, 0)

    def decision_function(self, X: np.ndarray) -> np.ndarray:
        """Returns anomaly scores (lower scores indicate higher anomaly severity)."""
        return self.model.decision_function(X)

    def save(self, filepath: str) -> None:
        """Serializes detector to disk."""
        joblib.dump(self, filepath)

    @staticmethod
    def load(filepath: str) -> "ZeroDayAnomalyDetector":
        """Loads serialized detector from disk."""
        return joblib.load(filepath)
