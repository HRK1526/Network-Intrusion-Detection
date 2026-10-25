"""
Module: network_intrusion_detection.py
Author: IBM SkillsBuild Cyber Security Team / BharatCares Project
Date: October 2026
Purpose: End-to-end Network Intrusion Detection & Threat Intelligence Pipeline.
"""

import os
import sys
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, IsolationForest
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, f1_score
from sklearn.preprocessing import StandardScaler, LabelEncoder
import joblib

def run_cybersecurity_pipeline():
    """Executes the full cyber threat detection, training, evaluation, and mitigation pipeline."""
    if sys.platform.startswith("win"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass
    print("=" * 80)
    print("[SEC] IBM SkillsBuild Cyber Security 2026 | BharatCares")
    print("[SEC] AI-Driven Network Intrusion Detection & SOC Threat Intelligence Platform")
    print("=" * 80)

    # 1. Dataset Loading
    base_dir = os.path.dirname(os.path.abspath(__file__))
    data_path = os.path.join(base_dir, "data", "network_traffic.csv")
    
    if not os.path.exists(data_path):
        print(f"Dataset not found at {data_path}. Generating now...")
        sys.path.append(os.path.join(base_dir, "src"))
        from dataset_generator import generate_network_traffic_dataset
        df = generate_network_traffic_dataset(num_samples=15000)
        os.makedirs(os.path.dirname(data_path), exist_ok=True)
        df.to_csv(data_path, index=False)
    else:
        df = pd.read_csv(data_path)

    print(f"\n[+] Network flow dataset loaded successfully: {df.shape[0]} samples, {df.shape[1]} features.")
    print("\n[+] Threat Distribution:")
    print(df["attack_type"].value_counts())

    # 2. Feature Preprocessing
    print("\n[+] Preprocessing network flow telemetry (Encoding & Normalization)...")
    categorical_cols = ["protocol_type", "service", "flag"]
    numeric_cols = [
        "duration", "src_bytes", "dst_bytes", "count", "srv_count",
        "serror_rate", "same_srv_rate", "diff_srv_rate",
        "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_serror_rate"
    ]

    encoders = {}
    encoded_cats = []
    for col in categorical_cols:
        le = LabelEncoder()
        encoded = le.fit_transform(df[col].astype(str))
        encoders[col] = le
        encoded_cats.append(encoded.reshape(-1, 1))

    scaler = StandardScaler()
    scaled_num = scaler.fit_transform(df[numeric_cols].values)
    X = np.hstack([scaled_num] + encoded_cats)

    label_enc = LabelEncoder()
    y_multi = label_enc.fit_transform(df["attack_type"])
    y_binary = df["label"].values

    # 3. Train-Test Split (80/20)
    X_train, X_test, y_train, y_test, y_train_b, y_test_b = train_test_split(
        X, y_multi, y_binary, test_size=0.20, random_state=42, stratify=y_multi
    )

    # 4. Model Training & Evaluation
    print("\n[+] Training Machine Learning Classifiers...")
    models = {
        "Random Forest Classifier": RandomForestClassifier(n_estimators=100, max_depth=16, random_state=42),
        "Decision Tree Classifier": DecisionTreeClassifier(max_depth=12, random_state=42),
        "Logistic Regression": LogisticRegression(max_iter=1000, random_state=42)
    }

    results = {}
    for name, model in models.items():
        model.fit(X_train, y_train)
        preds = model.predict(X_test)
        acc = accuracy_score(y_test, preds)
        f1 = f1_score(y_test, preds, average="weighted")
        results[name] = {"accuracy": acc, "f1_score": f1, "model": model}
        print(f" -> {name:30s} | Test Accuracy: {acc * 100:.2f}% | Weighted F1: {f1:.4f}")

    # 5. Unsupervised Anomaly Detection (Isolation Forest)
    print("\n[+] Training Unsupervised Isolation Forest for Zero-Day Threat Detection...")
    iso = IsolationForest(n_estimators=100, contamination=0.48, random_state=42)
    iso.fit(X_train)
    iso_preds = np.where(iso.predict(X_test) == -1, 1, 0)
    iso_acc = accuracy_score(y_test_b, iso_preds)
    iso_f1 = f1_score(y_test_b, iso_preds)
    print(f" -> Isolation Forest (Zero-Day)   | Accuracy: {iso_acc * 100:.2f}% | Binary F1: {iso_f1:.4f}")

    # 6. Detailed Evaluation for Best Model
    best_clf = results["Random Forest Classifier"]["model"]
    y_pred_best = best_clf.predict(X_test)
    class_names = [str(c) for c in label_enc.classes_]

    print("\n" + "=" * 80)
    print("📊 CLASSIFICATION REPORT (Random Forest - Champion Model)")
    print("=" * 80)
    print(classification_report(y_test, y_pred_best, target_names=class_names))

    # 7. Simulated SOC Threat Scenario & Automated Containment
    print("=" * 80)
    print("🚨 SIMULATED LIVE SOC INCIDENT RESPONSE & MITRE ATT&CK MAPPING")
    print("=" * 80)
    sample_flow = X_test[0:1]
    pred_class_idx = best_clf.predict(sample_flow)[0]
    pred_threat_name = label_enc.inverse_transform([pred_class_idx])[0]

    sys.path.append(os.path.join(base_dir, "src"))
    from incident_responder import IncidentResponseEngine
    incident = IncidentResponseEngine.generate_incident_report(
        attack_type=pred_threat_name,
        confidence=0.99,
        src_ip="203.0.113.45",
        dst_ip="198.51.100.10"
    )

    print(f"Incident Ticket       : {incident['incident_id']}")
    print(f"Detected Attack       : {incident['detected_threat']}")
    print(f"Severity Level        : {incident['severity']}")
    print(f"MITRE Technique       : {incident['mitre_technique_id']} - {incident['mitre_technique_name']}")
    print(f"Containment Action    : {incident['recommended_containment']}")
    print(f"Automated Firewall Rule: {incident['automated_firewall_mitigation']}")
    print("=" * 80)
    print("✅ Cyber Security Pipeline Execution Successfully Completed.")

if __name__ == "__main__":
    run_cybersecurity_pipeline()
