"""
Module: feature_engineering.py
Author: IBM SkillsBuild Cyber Security Team / BharatCares Project
Date: October 2026
Purpose: Feature preprocessing, categorical encoding, and scaling pipeline for Network Intrusion Detection.
"""

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder
import joblib
import os
from typing import Tuple, Dict, Any, List

class CyberFeaturePipeline:
    """
    Robust preprocessing and feature engineering pipeline for network intrusion flow telemetry.
    """

    def __init__(self):
        """Initializes encoders and scaler."""
        self.scaler = StandardScaler()
        self.categorical_cols = ["protocol_type", "service", "flag"]
        self.numeric_cols = [
            "duration", "src_bytes", "dst_bytes", "count", "srv_count",
            "serror_rate", "same_srv_rate", "diff_srv_rate",
            "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_serror_rate"
        ]
        self.encoders: Dict[str, LabelEncoder] = {}
        self.label_encoder = LabelEncoder()
        self.is_fitted = False

    def fit_transform(self, df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """
        Fits encoders and scaler on dataframe and transforms features.

        Args:
            df (pd.DataFrame): Raw network traffic dataframe.

        Returns:
            Tuple[np.ndarray, np.ndarray, np.ndarray]:
                - X_scaled (np.ndarray): Scaled feature matrix
                - y_binary (np.ndarray): Binary intrusion labels (0=Normal, 1=Malicious)
                - y_multi (np.ndarray): Multi-class attack labels encoded as integers
        """
        df_copy = df.copy()

        # Fit and transform categorical features
        encoded_cats = []
        for col in self.categorical_cols:
            le = LabelEncoder()
            # Convert to string and fit
            vals = df_copy[col].astype(str)
            transformed = le.fit_transform(vals)
            self.encoders[col] = le
            encoded_cats.append(transformed.reshape(-1, 1))

        encoded_cats_arr = np.hstack(encoded_cats)

        # Scale numerical features
        numeric_arr = df_copy[self.numeric_cols].values
        scaled_numerics = self.scaler.fit_transform(numeric_arr)

        # Combine features: scaled numerics + encoded categoricals
        X = np.hstack([scaled_numerics, encoded_cats_arr])

        # Target variables
        y_binary = df_copy["label"].values
        y_multi = self.label_encoder.fit_transform(df_copy["attack_type"].astype(str))

        self.is_fitted = True
        return X, y_binary, y_multi

    def transform(self, df: pd.DataFrame) -> np.ndarray:
        """
        Transforms incoming telemetry data using pre-fitted transformers.

        Args:
            df (pd.DataFrame): Incoming network flow records.

        Returns:
            np.ndarray: Scaled feature matrix.
        """
        if not self.is_fitted:
            raise ValueError("Pipeline has not been fitted yet. Call fit_transform first.")

        df_copy = df.copy()
        encoded_cats = []
        for col in self.categorical_cols:
            le = self.encoders[col]
            vals = df_copy[col].astype(str)
            # Handle unseen labels gracefully by mapping to known classes or first class
            transformed = []
            known_classes = set(le.classes_)
            fallback = le.classes_[0]
            for v in vals:
                transformed.append(v if v in known_classes else fallback)
            encoded = le.transform(transformed)
            encoded_cats.append(encoded.reshape(-1, 1))

        encoded_cats_arr = np.hstack(encoded_cats)
        numeric_arr = df_copy[self.numeric_cols].values
        scaled_numerics = self.scaler.transform(numeric_arr)

        return np.hstack([scaled_numerics, encoded_cats_arr])

    def get_feature_names(self) -> List[str]:
        """Returns the ordered list of feature column names."""
        return self.numeric_cols + self.categorical_cols

    def save(self, filepath: str) -> None:
        """Serializes pipeline state to disk."""
        joblib.dump(self, filepath)

    @staticmethod
    def load(filepath: str) -> "CyberFeaturePipeline":
        """Loads serialized pipeline state from disk."""
        return joblib.load(filepath)
