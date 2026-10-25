"""
Module: model_trainer.py
Author: IBM SkillsBuild Cyber Security Team / BharatCares Project
Date: October 2026
Purpose: Training, comparative evaluation, and model serialization for Cyber Threat Detection.
"""

import os
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, Tuple
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    classification_report, confusion_matrix
)

from feature_engineering import CyberFeaturePipeline
from anomaly_detector import ZeroDayAnomalyDetector

class ThreatModelTrainer:
    """
    Comprehensive training and evaluation harness for Network Intrusion Detection models.
    """

    def __init__(self, data_path: str, models_dir: str):
        """
        Initializes trainer with file paths.

        Args:
            data_path (str): Path to network traffic CSV.
            models_dir (str): Path to store trained models.
        """
        self.data_path = data_path
        self.models_dir = models_dir
        os.makedirs(self.models_dir, exist_ok=True)
        self.pipeline = CyberFeaturePipeline()
        self.trained_models: Dict[str, Any] = {}
        self.evaluation_results: Dict[str, Dict[str, float]] = {}

    def load_and_preprocess(self) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """Loads data and performs feature extraction and train-test splits."""
        df = pd.read_csv(self.data_path)
        X, y_bin, y_multi = self.pipeline.fit_transform(df)

        # Train/Test Split (80% train, 20% test)
        X_train, X_test, y_train_m, y_test_m, y_train_b, y_test_b = train_test_split(
            X, y_multi, y_bin, test_size=0.20, random_state=42, stratify=y_multi
        )

        return X_train, X_test, y_train_m, y_test_m, y_train_b, y_test_b

    def train_and_evaluate_all(self) -> Dict[str, Any]:
        """
        Trains Random Forest, Decision Tree, Gradient Boosting, and Logistic Regression models.
        Evaluates and saves the best model.
        """
        X_train, X_test, y_train, y_test, y_train_b, y_test_b = self.load_and_preprocess()

        classifiers = {
            "Random_Forest": RandomForestClassifier(n_estimators=100, max_depth=16, random_state=42, n_jobs=-1),
            "Decision_Tree": DecisionTreeClassifier(max_depth=12, random_state=42),
            "Gradient_Boosting": GradientBoostingClassifier(n_estimators=80, max_depth=5, random_state=42),
            "Logistic_Regression": LogisticRegression(max_iter=1000, random_state=42)
        }

        best_f1 = 0.0
        best_model_name = ""

        for name, clf in classifiers.items():
            print(f"Training {name}...")
            clf.fit(X_train, y_train)
            y_pred = clf.predict(X_test)

            acc = accuracy_score(y_test, y_pred)
            prec = precision_score(y_test, y_pred, average="weighted", zero_division=0)
            rec = recall_score(y_test, y_pred, average="weighted", zero_division=0)
            f1 = f1_score(y_test, y_pred, average="weighted", zero_division=0)

            self.evaluation_results[name] = {
                "accuracy": round(float(acc), 4),
                "precision": round(float(prec), 4),
                "recall": round(float(rec), 4),
                "f1_score": round(float(f1), 4)
            }
            self.trained_models[name] = clf

            if f1 > best_f1:
                best_f1 = f1
                best_model_name = name

        # Train Unsupervised Isolation Forest Anomaly Detector
        print("Training Unsupervised Isolation Forest Anomaly Detector...")
        iso_detector = ZeroDayAnomalyDetector(contamination=0.48, random_state=42)
        iso_detector.fit(X_train)
        iso_preds = iso_detector.predict(X_test)
        iso_f1 = f1_score(y_test_b, iso_preds, average="binary")
        self.evaluation_results["Isolation_Forest_Unsupervised"] = {
            "accuracy": round(float(accuracy_score(y_test_b, iso_preds)), 4),
            "precision": round(float(precision_score(y_test_b, iso_preds)), 4),
            "recall": round(float(recall_score(y_test_b, iso_preds)), 4),
            "f1_score": round(float(iso_f1), 4)
        }

        # Save Best Model, Feature Pipeline, and Anomaly Detector
        best_model = self.trained_models[best_model_name]
        joblib.dump(best_model, os.path.join(self.models_dir, "best_nids_model.joblib"))
        self.pipeline.save(os.path.join(self.models_dir, "feature_pipeline.joblib"))
        iso_detector.save(os.path.join(self.models_dir, "anomaly_detector.joblib"))

        # Save detailed classification report for the best model
        y_pred_best = best_model.predict(X_test)
        target_names = [str(cls) for cls in self.pipeline.label_encoder.classes_]
        report = classification_report(y_test, y_pred_best, target_names=target_names, output_dict=True)
        conf_matrix = confusion_matrix(y_test, y_pred_best).tolist()

        summary = {
            "best_model": best_model_name,
            "metrics": self.evaluation_results,
            "best_model_report": report,
            "confusion_matrix": conf_matrix,
            "classes": target_names
        }

        joblib.dump(summary, os.path.join(self.models_dir, "evaluation_summary.joblib"))
        print(f"Model training complete. Best model: {best_model_name} (F1: {best_f1:.4f})")
        return summary

if __name__ == "__main__":
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(current_dir)
    data_file = os.path.join(project_root, "data", "network_traffic.csv")
    models_path = os.path.join(project_root, "models")

    trainer = ThreatModelTrainer(data_path=data_file, models_dir=models_path)
    res = trainer.train_and_evaluate_all()
    print("Benchmark Results Summary:")
    for model_name, metrics in res["metrics"].items():
        print(f" - {model_name:30s}: Acc: {metrics['accuracy']:.4f} | Prec: {metrics['precision']:.4f} | Rec: {metrics['recall']:.4f} | F1: {metrics['f1_score']:.4f}")
