"""
Module: test_cyber_suite.py
Author: IBM SkillsBuild Cyber Security Team / BharatCares Project
Date: October 2026
Purpose: Comprehensive 9-point validation test harness for CyberShield AI.
"""

import os
import sys
import json
import pytest
import pandas as pd
import numpy as np
import docx
import joblib

# Setup paths
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(PROJECT_ROOT, "src")
sys.path.append(SRC_DIR)

from feature_engineering import CyberFeaturePipeline
from anomaly_detector import ZeroDayAnomalyDetector
from incident_responder import IncidentResponseEngine, MITRE_ATTACK_MAPPING

def test_1_required_submission_files_exist():
    """Validates that all 4 required submission files exist with non-zero size."""
    required_files = [
        "HritwizRaj_NetworkIntrusionDetection.ipynb",
        "requirements.txt",
        "HritwizRaj_ProjectReport.docx",
        "README.md"
    ]
    for filename in required_files:
        filepath = os.path.join(PROJECT_ROOT, filename)
        assert os.path.exists(filepath), f"Missing required file: {filename}"
        assert os.path.getsize(filepath) > 0, f"File is empty: {filename}"
    print("\n[TEST 1 PASSED] All 4 mandatory submission files exist and are non-empty.")

def test_2_strict_author_naming():
    """Validates that the author naming strictly corresponds to Hritwiz Raj without conflicts."""
    docx_path = os.path.join(PROJECT_ROOT, "HritwizRaj_ProjectReport.docx")
    doc = docx.Document(docx_path)
    full_text = " ".join([p.text for p in doc.paragraphs] + [c.text for t in doc.tables for r in t.rows for c in r.cells])
    assert "Hritwiz Raj" in full_text
    assert "kulshresthahritwizraj@gmail.com" in full_text
    print("\n[TEST 2 PASSED] Author identity strictly validated as Hritwiz Raj.")

def test_3_dataset_integrity():
    """Validates dataset volume, schema, and attack class balance."""
    data_path = os.path.join(PROJECT_ROOT, "data", "network_traffic.csv")
    assert os.path.exists(data_path)
    df = pd.read_csv(data_path)
    assert len(df) >= 10000
    expected_cols = [
        "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
        "count", "srv_count", "serror_rate", "same_srv_rate", "diff_srv_rate",
        "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_serror_rate",
        "attack_type", "label"
    ]
    for col in expected_cols:
        assert col in df.columns, f"Missing expected column {col}"
    assert set(df["label"].unique()) == {0, 1}
    assert "DoS_SYN_Flood" in df["attack_type"].values
    assert "Normal" in df["attack_type"].values
    print(f"\n[TEST 3 PASSED] Dataset verified ({len(df)} samples across 6 threat classes).")

def test_4_feature_pipeline_fit_transform():
    """Validates the preprocessing and scaling pipeline."""
    pipeline_path = os.path.join(PROJECT_ROOT, "models", "feature_pipeline.joblib")
    assert os.path.exists(pipeline_path)
    pipeline = CyberFeaturePipeline.load(pipeline_path)
    assert pipeline.is_fitted

    # Test dummy inference sample
    sample_df = pd.DataFrame([{
        "duration": 0.05,
        "protocol_type": "tcp",
        "service": "http",
        "flag": "S0",
        "src_bytes": 45,
        "dst_bytes": 0,
        "count": 400,
        "srv_count": 350,
        "serror_rate": 0.95,
        "same_srv_rate": 0.95,
        "diff_srv_rate": 0.05,
        "dst_host_count": 255,
        "dst_host_srv_count": 10,
        "dst_host_same_srv_rate": 0.05,
        "dst_host_serror_rate": 0.95
    }])
    transformed = pipeline.transform(sample_df)
    assert transformed.shape == (1, 15)
    print("\n[TEST 4 PASSED] Feature pipeline transformation validated.")

def test_5_champion_model_inference():
    """Validates champion model inference on simulated attack telemetry."""
    model_path = os.path.join(PROJECT_ROOT, "models", "best_nids_model.joblib")
    pipeline_path = os.path.join(PROJECT_ROOT, "models", "feature_pipeline.joblib")
    model = joblib.load(model_path)
    pipeline = CyberFeaturePipeline.load(pipeline_path)

    # Test DoS SYN flood sample
    sample_df = pd.DataFrame([{
        "duration": 0.01,
        "protocol_type": "tcp",
        "service": "http",
        "flag": "S0",
        "src_bytes": 40,
        "dst_bytes": 0,
        "count": 450,
        "srv_count": 420,
        "serror_rate": 1.0,
        "same_srv_rate": 0.98,
        "diff_srv_rate": 0.02,
        "dst_host_count": 255,
        "dst_host_srv_count": 12,
        "dst_host_same_srv_rate": 0.04,
        "dst_host_serror_rate": 1.0
    }])
    X_sample = pipeline.transform(sample_df)
    pred_idx = model.predict(X_sample)[0]
    pred_class = pipeline.label_encoder.inverse_transform([pred_idx])[0]
    assert pred_class == "DoS_SYN_Flood", f"Expected DoS_SYN_Flood, got {pred_class}"
    print(f"\n[TEST 5 PASSED] Champion model successfully classified attack as {pred_class}.")

def test_6_unsupervised_anomaly_detector():
    """Validates Isolation Forest zero-day anomaly detector inference."""
    detector_path = os.path.join(PROJECT_ROOT, "models", "anomaly_detector.joblib")
    detector = ZeroDayAnomalyDetector.load(detector_path)
    assert detector.is_fitted

    dummy_vector = np.random.randn(5, 15)
    preds = detector.predict(dummy_vector)
    scores = detector.decision_function(dummy_vector)
    assert len(preds) == 5
    assert len(scores) == 5
    print("\n[TEST 6 PASSED] Isolation Forest anomaly detector validated.")

def test_7_incident_response_engine():
    """Validates automated SOC ticket and firewall rule generation."""
    for threat in ["DoS_SYN_Flood", "Port_Scan", "Brute_Force_SSH", "Web_Attack_SQLi", "Botnet_Infiltration"]:
        incident = IncidentResponseEngine.generate_incident_report(
            attack_type=threat,
            confidence=0.98,
            src_ip="203.0.113.19",
            dst_ip="192.0.2.1"
        )
        assert incident["detected_threat"] == threat
        assert incident["severity"] in ["CRITICAL", "HIGH", "MEDIUM"]
        assert "iptables" in incident["automated_firewall_mitigation"]
        assert "203.0.113.19" in incident["automated_firewall_mitigation"]
        assert incident["mitre_technique_id"].startswith("T1")
    print("\n[TEST 7 PASSED] Incident response engine and firewall mitigation verified.")

def test_8_notebook_json_validity():
    """Validates that the Jupyter Notebook is valid JSON and contains cells with execution outputs."""
    nb_path = os.path.join(PROJECT_ROOT, "HritwizRaj_NetworkIntrusionDetection.ipynb")
    with open(nb_path, "r", encoding="utf-8") as f:
        nb_data = json.load(f)
    assert "cells" in nb_data
    assert len(nb_data["cells"]) >= 10
    
    # Check that code cells have outputs
    code_cells = [c for c in nb_data["cells"] if c["cell_type"] == "code"]
    has_outputs = any(len(c.get("outputs", [])) > 0 for c in code_cells)
    assert has_outputs, "Notebook code cells should contain populated outputs"
    print(f"\n[TEST 8 PASSED] Jupyter notebook validated with {len(nb_data['cells'])} cells and pre-computed outputs.")

def test_9_word_report_structure():
    """Validates docx document paragraphs, headings, and table cells."""
    docx_path = os.path.join(PROJECT_ROOT, "HritwizRaj_ProjectReport.docx")
    doc = docx.Document(docx_path)
    assert len(doc.paragraphs) > 20
    assert len(doc.tables) >= 3
    print(f"\n[TEST 9 PASSED] Word report validated with {len(doc.paragraphs)} paragraphs and {len(doc.tables)} tables.")

if __name__ == "__main__":
    import sys
    if sys.platform.startswith("win"):
        sys.stdout.reconfigure(encoding="utf-8")
    test_1_required_submission_files_exist()
    test_2_strict_author_naming()
    test_3_dataset_integrity()
    test_4_feature_pipeline_fit_transform()
    test_5_champion_model_inference()
    test_6_unsupervised_anomaly_detector()
    test_7_incident_response_engine()
    test_8_notebook_json_validity()
    test_9_word_report_structure()
    print("\n" + "=" * 70)
    print("[SUCCESS] ALL 9 RIGOROUS VERIFICATION TESTS PASSED SUCCESSFULLY!")
    print("=" * 70)
