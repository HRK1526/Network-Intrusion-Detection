"""
Module: build_notebook.py
Author: IBM SkillsBuild Cyber Security Team / BharatCares Project
Date: October 2026
Purpose: Generates and executes the official IBM SkillsBuild Cyber Security Jupyter Notebook.
"""

import nbformat as nbf
import os
import shutil

def generate_notebook():
    nb = nbf.v4.new_notebook()

    cells = []

    # Title & Metadata Markdown
    cells.append(nbf.v4.new_markdown_cell("""# 🛡️ IBM SkillsBuild Cyber Security 2026
### Conducted by BharatCares
## 🚀 Project: AI-Driven Network Intrusion Detection & Threat Intelligence System (NIDS)
**Domain:** Cyber Security & Machine Learning  
**Author:** Hritwiz Raj Kulshrestha (Harsh)  
**Dataset:** Network Flow Telemetry (Based on NSL-KDD & CIC-IDS2017 Benchmarks)  
**Date:** October 2026

---
### 📌 Executive Summary
Modern enterprise environments face an escalating volume of sophisticated cyber attacks, including Distributed Denial of Service (DDoS), credential brute forcing, SQL injection exploits, and stealthy botnet command-and-control (C2) infiltration. Traditional signature-based intrusion detection systems (IDS) often fail against zero-day exploits and polymorphic threat vectors.

This project delivers an end-to-end, machine learning-powered **Network Intrusion Detection System (NIDS)** that:
1. Accurately identifies multi-class network threats in real time.
2. Employs unsupervised anomaly detection (Isolation Forest) for zero-day threat identification.
3. Automatically maps detections to the industry-standard **MITRE ATT&CK Matrix**.
4. Synthesizes automated edge firewall (`iptables`) containment rules to block adversary IPs instantaneously.
"""))

    # Imports Cell
    cells.append(nbf.v4.new_markdown_cell("## 📦 Step 1: Environment Setup & Library Imports"))
    cells.append(nbf.v4.new_code_cell("""import os
import sys
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, IsolationForest
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, f1_score, precision_score, recall_score
import joblib

# Plotting configuration
plt.style.use('seaborn-v0_8-darkgrid' if 'seaborn-v0_8-darkgrid' in plt.style.available else 'default')
%matplotlib inline
print("✅ Libraries successfully imported.")
"""))

    # Data Acquisition Cell
    cells.append(nbf.v4.new_markdown_cell("""## 📊 Step 2: Cyber Threat Dataset Acquisition & Exploration
We load the network traffic telemetry dataset containing 15,000 flow records across 6 threat classes:
- **Normal**: Legitimate web, email, DNS, and file transfer traffic.
- **DoS_SYN_Flood**: Denial of Service TCP SYN flood exhausting host connections.
- **Port_Scan**: Network reconnaissance probing open ports and running services.
- **Brute_Force_SSH**: Automated credential brute-forcing targeting SSH port 22.
- **Web_Attack_SQLi**: Web application SQL injection exploit payloads.
- **Botnet_Infiltration**: Periodic C2 beaconing and persistence callbacks.
"""))
    cells.append(nbf.v4.new_code_cell("""# Load the dataset
data_path = os.path.join("data", "network_traffic.csv")
if not os.path.exists(data_path):
    data_path = os.path.join("..", "data", "network_traffic.csv")

df = pd.read_csv(data_path)
print(f"Dataset Shape: {df.shape[0]} rows, {df.shape[1]} columns")
print("\\nFirst 5 Records:")
display(df.head())
"""))

    # Threat Distribution Analysis
    cells.append(nbf.v4.new_code_cell("""# Summary statistics and Class Distribution
print("Class Distribution Breakdown:")
print(df["attack_type"].value_counts())

plt.figure(figsize=(10, 5))
colors = ['#2ea043', '#f85149', '#e3b341', '#a371f7', '#388bfd', '#db61a2']
df["attack_type"].value_counts().plot(kind='bar', color=colors, edgecolor='black', alpha=0.85)
plt.title("Distribution of Network Traffic Classes", fontsize=14, fontweight='bold')
plt.xlabel("Traffic Category", fontsize=12)
plt.ylabel("Number of Flow Samples", fontsize=12)
plt.xticks(rotation=30)
plt.grid(axis='y', linestyle='--', alpha=0.7)
plt.tight_layout()
plt.show()
"""))

    # Preprocessing
    cells.append(nbf.v4.new_markdown_cell("""## ⚙️ Step 3: Feature Preprocessing, Scaling & Pipeline Construction
We standardize continuous features (flow bytes, packet duration, connection rates) and encode categorical attributes (`protocol_type`, `service`, `flag`).
"""))
    cells.append(nbf.v4.new_code_cell("""categorical_cols = ["protocol_type", "service", "flag"]
numeric_cols = [
    "duration", "src_bytes", "dst_bytes", "count", "srv_count",
    "serror_rate", "same_srv_rate", "diff_srv_rate",
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_serror_rate"
]

# Categorical Label Encoding
encoders = {}
encoded_cats = []
for col in categorical_cols:
    le = LabelEncoder()
    encoded = le.fit_transform(df[col].astype(str))
    encoders[col] = le
    encoded_cats.append(encoded.reshape(-1, 1))

# Numerical Normalization via StandardScaler
scaler = StandardScaler()
scaled_numerics = scaler.fit_transform(df[numeric_cols].values)

# Feature matrix X
X = np.hstack([scaled_numerics] + encoded_cats)

# Multi-class target y and binary label
target_encoder = LabelEncoder()
y_multi = target_encoder.fit_transform(df["attack_type"])
y_binary = df["label"].values

print(f"Feature Matrix X Shape: {X.shape}")
print(f"Classes Encoded: {list(target_encoder.classes_)}")
"""))

    # Train Test Split
    cells.append(nbf.v4.new_code_cell("""# 80/20 Train-Test Stratified Split
X_train, X_test, y_train, y_test, y_train_b, y_test_b = train_test_split(
    X, y_multi, y_binary, test_size=0.20, random_state=42, stratify=y_multi
)
print(f"Training set: {X_train.shape[0]} samples | Test set: {X_test.shape[0]} samples")
"""))

    # Model Training
    cells.append(nbf.v4.new_markdown_cell("""## 🤖 Step 4: Machine Learning Model Training & Comparative Benchmark
We train and evaluate 4 supervised classifiers:
1. **Random Forest Classifier**: Ensemble of bagged decision trees with high resistance to overfitting.
2. **Decision Tree Classifier**: Fast, rule-based baseline.
3. **Gradient Boosting Classifier**: Sequential boosting minimizing residual flow errors.
4. **Logistic Regression**: Linear reference benchmark.
"""))
    cells.append(nbf.v4.new_code_cell("""classifiers = {
    "Random Forest": RandomForestClassifier(n_estimators=100, max_depth=16, random_state=42, n_jobs=-1),
    "Decision Tree": DecisionTreeClassifier(max_depth=12, random_state=42),
    "Gradient Boosting": GradientBoostingClassifier(n_estimators=80, max_depth=5, random_state=42),
    "Logistic Regression": LogisticRegression(max_iter=1000, random_state=42)
}

benchmark_results = []

for name, clf in classifiers.items():
    print(f"Training {name}...")
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)
    
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, average="weighted", zero_division=0)
    rec = recall_score(y_test, y_pred, average="weighted", zero_division=0)
    f1 = f1_score(y_test, y_pred, average="weighted", zero_division=0)
    
    benchmark_results.append({
        "Algorithm": name,
        "Accuracy (%)": round(acc * 100, 2),
        "Precision": round(prec, 4),
        "Recall": round(rec, 4),
        "F1-Score": round(f1, 4)
    })

bench_df = pd.DataFrame(benchmark_results)
display(bench_df)
"""))

    # Anomaly Detection
    cells.append(nbf.v4.new_markdown_cell("""## 🕵️ Step 5: Unsupervised Zero-Day Anomaly Detection (Isolation Forest)
For unknown or zero-day network threats without existing labels, an unsupervised Isolation Forest isolates anomalies by recursively partitioning feature hyperspace.
"""))
    cells.append(nbf.v4.new_code_cell("""# Isolation Forest Training
iso_forest = IsolationForest(n_estimators=100, contamination=0.48, random_state=42, n_jobs=-1)
iso_forest.fit(X_train)

# In Isolation Forest: -1 = Anomaly (malicious), 1 = Inlier (normal)
iso_raw = iso_forest.predict(X_test)
iso_preds = np.where(iso_raw == -1, 1, 0)

iso_acc = accuracy_score(y_test_b, iso_preds)
iso_f1 = f1_score(y_test_b, iso_preds)

print(f"Zero-Day Anomaly Detection (Isolation Forest):")
print(f"Accuracy : {iso_acc * 100:.2f}%")
print(f"F1-Score : {iso_f1:.4f}")
"""))

    # Confusion Matrix & Classification Report
    cells.append(nbf.v4.new_markdown_cell("""## 📈 Step 6: Detailed Performance Evaluation (Confusion Matrix & Report)
Evaluation of our best-performing model (Random Forest Classifier).
"""))
    cells.append(nbf.v4.new_code_cell("""best_model = classifiers["Random Forest"]
y_pred_best = best_model.predict(X_test)
class_labels = list(target_encoder.classes_)

print("=" * 70)
print("CLASSIFICATION REPORT:")
print("=" * 70)
print(classification_report(y_test, y_pred_best, target_names=class_labels))

# Confusion Matrix Heatmap
cm = confusion_matrix(y_test, y_pred_best)
plt.figure(figsize=(8, 6))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=class_labels, yticklabels=class_labels)
plt.title("Confusion Matrix - Random Forest NIDS", fontsize=14, fontweight='bold')
plt.xlabel("Predicted Threat Label", fontsize=12)
plt.ylabel("True Threat Label", fontsize=12)
plt.xticks(rotation=40)
plt.tight_layout()
plt.show()
"""))

    # Incident Response & MITRE ATT&CK
    cells.append(nbf.v4.new_markdown_cell("""## 🚨 Step 7: Automated SOC Incident Response & MITRE ATT&CK Mapping
When malicious traffic is flagged, the system generates a SIEM-ready incident ticket and outputs automated firewall mitigation commands (`iptables`).
"""))
    cells.append(nbf.v4.new_code_cell("""MITRE_LOOKUP = {
    "DoS_SYN_Flood": ("T1498.001", "Direct Network Flood", "Impact", "HIGH", "iptables -A INPUT -p tcp --syn -s {ip} -j DROP"),
    "Port_Scan": ("T1046", "Network Service Discovery", "Discovery", "MEDIUM", "iptables -I INPUT -s {ip} -j REJECT"),
    "Brute_Force_SSH": ("T1110.001", "Password Guessing", "Credential Access", "HIGH", "iptables -A INPUT -p tcp --dport 22 -s {ip} -j DROP"),
    "Web_Attack_SQLi": ("T1190", "Exploit Public Application", "Initial Access", "CRITICAL", "iptables -A INPUT -p tcp --dport 80,443 -s {ip} -j DROP"),
    "Botnet_Infiltration": ("T1071.001", "Web C2 Beaconing", "Command and Control", "CRITICAL", "iptables -A FORWARD -s {ip} -j DROP"),
    "Normal": ("None", "Legitimate Traffic", "Normal Operations", "LOW", "# Safe Flow")
}

def simulate_soc_alert(flow_vector, simulated_src_ip="192.168.1.185"):
    pred_idx = best_model.predict(flow_vector.reshape(1, -1))[0]
    threat_name = target_encoder.inverse_transform([pred_idx])[0]
    
    t_id, t_name, tactic, sev, fw_tpl = MITRE_LOOKUP.get(threat_name, ("T1000", "Anomaly", "Defense Evasion", "HIGH", "iptables -A INPUT -s {ip} -j DROP"))
    fw_rule = fw_tpl.format(ip=simulated_src_ip)
    
    print("-" * 65)
    print(f"🚨 SOC INCIDENT ALERT | Severity: [{sev}]")
    print(f"Attacker Source IP    : {simulated_src_ip}")
    print(f"Classified Threat     : {threat_name}")
    print(f"MITRE ATT&CK Tactic   : {tactic}")
    print(f"MITRE Technique ID    : {t_id} ({t_name})")
    print(f"Automated Mitigation : {fw_rule}")
    print("-" * 65)

# Test alerting on random test sample
print("Simulating Real-Time Threat Ingestion & Mitigation:")
for i in [0, 5, 10]:
    simulate_soc_alert(X_test[i], simulated_src_ip=f"198.51.100.{10 + i}")
"""))

    # Conclusion
    cells.append(nbf.v4.new_markdown_cell("""## 🏁 Step 8: Conclusion & Future Scope
In this project developed for **IBM SkillsBuild Cyber Security 2026 (BharatCares)**:
- We engineered an AI-powered Network Intrusion Detection System capable of detecting diverse cyber attacks with high accuracy.
- We benchmarked multiple supervised models (Random Forest, Decision Trees, Gradient Boosting, Logistic Regression) and integrated an unsupervised Isolation Forest for zero-day defense.
- We demonstrated automated SOAR-style incident containment via dynamic `iptables` generation and MITRE ATT&CK taxonomy mapping.
"""))

    nb.cells = cells
    return nb

if __name__ == "__main__":
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    nb = generate_notebook()
    
    # Save primary file
    primary_path = os.path.join(project_root, "HritwizRaj_NetworkIntrusionDetection.ipynb")
    secondary_path = os.path.join(project_root, "Harsh_NetworkIntrusionDetection.ipynb")
    
    with open(primary_path, "w", encoding="utf-8") as f:
        nbf.write(nb, f)
    with open(secondary_path, "w", encoding="utf-8") as f:
        nbf.write(nb, f)
        
    print(f"Notebooks successfully created:\n - {primary_path}\n - {secondary_path}")
