"""
Module: dataset_generator.py
Author: IBM SkillsBuild Cyber Security Team / BharatCares Project
Date: October 2026
Purpose: Generate synthetic yet statistically rigorous Network Intrusion Detection System (NIDS) 
         telemetry based on NSL-KDD and CIC-IDS2017 cybersecurity benchmarks.
"""

import numpy as np
import pandas as pd
import os

def generate_network_traffic_dataset(num_samples: int = 12000, random_seed: int = 42) -> pd.DataFrame:
    """
    Generates a realistic network intrusion dataset with legitimate and malicious flow patterns.

    Args:
        num_samples (int): Total number of network flow records to generate.
        random_seed (int): Seed for reproducibility.

    Returns:
        pd.DataFrame: High-fidelity network flow telemetry dataframe.
    """
    np.random.seed(random_seed)

    # Class distributions: Normal (55%), DoS (20%), Port Scan (12%), Brute Force (7%), Web Attack (4%), Botnet (2%)
    categories = [
        "Normal", 
        "DoS_SYN_Flood", 
        "Port_Scan", 
        "Brute_Force_SSH", 
        "Web_Attack_SQLi", 
        "Botnet_Infiltration"
    ]
    probabilities = [0.52, 0.20, 0.13, 0.07, 0.05, 0.03]

    chosen_categories = np.random.choice(categories, size=num_samples, p=probabilities)

    data = []

    for cat in chosen_categories:
        if cat == "Normal":
            proto = np.random.choice(["tcp", "udp"], p=[0.75, 0.25])
            serv = np.random.choice(["http", "https", "dns", "smtp", "ssh"], p=[0.50, 0.30, 0.10, 0.05, 0.05])
            flag = np.random.choice(["SF", "OTH"], p=[0.97, 0.03])
            duration = np.random.exponential(scale=2.5)
            src_bytes = int(np.random.gamma(shape=2.0, scale=350.0))
            dst_bytes = int(np.random.gamma(shape=3.0, scale=1200.0))
            count = int(np.random.poisson(lam=4))
            srv_count = max(1, int(np.random.poisson(lam=4)))
            serror_rate = float(np.random.beta(a=0.5, b=50.0))
            same_srv_rate = float(np.random.uniform(0.85, 1.0))
            diff_srv_rate = float(np.random.uniform(0.0, 0.15))
            dst_host_count = int(np.random.randint(10, 255))
            dst_host_srv_count = min(dst_host_count, int(np.random.randint(10, dst_host_count + 1)))
            dst_host_same_srv_rate = float(np.random.uniform(0.8, 1.0))
            dst_host_serror_rate = float(np.random.beta(a=0.5, b=40.0))
            label = 0

        elif cat == "DoS_SYN_Flood":
            proto = "tcp"
            serv = np.random.choice(["http", "https", "tcp"], p=[0.6, 0.3, 0.1])
            flag = "S0" # SYN with no ACK response
            duration = float(np.random.uniform(0.0, 0.05)) # Rapid-fire packets
            src_bytes = int(np.random.uniform(0, 100)) # Empty or minimal payload
            dst_bytes = 0 # No response received
            count = int(np.random.randint(250, 512)) # Massive burst rate
            srv_count = int(np.random.randint(200, 512))
            serror_rate = float(np.random.uniform(0.90, 1.0)) # Massive SYN errors
            same_srv_rate = float(np.random.uniform(0.90, 1.0))
            diff_srv_rate = float(np.random.uniform(0.0, 0.05))
            dst_host_count = 255 # Saturated host table
            dst_host_srv_count = int(np.random.randint(1, 30))
            dst_host_same_srv_rate = float(np.random.uniform(0.01, 0.1))
            dst_host_serror_rate = float(np.random.uniform(0.90, 1.0))
            label = 1

        elif cat == "Port_Scan":
            proto = np.random.choice(["tcp", "icmp"], p=[0.85, 0.15])
            serv = np.random.choice(["other", "http", "ftp", "telnet"], p=[0.7, 0.1, 0.1, 0.1])
            flag = np.random.choice(["REJ", "RSTO", "S0"], p=[0.5, 0.3, 0.2])
            duration = float(np.random.uniform(0.0, 0.1))
            src_bytes = int(np.random.uniform(0, 64))
            dst_bytes = 0
            count = int(np.random.randint(100, 350))
            srv_count = int(np.random.randint(1, 5)) # Connecting to many different ports/services
            serror_rate = float(np.random.uniform(0.4, 0.8))
            same_srv_rate = float(np.random.uniform(0.01, 0.15))
            diff_srv_rate = float(np.random.uniform(0.70, 0.99)) # Very high diff service rate!
            dst_host_count = 255
            dst_host_srv_count = int(np.random.randint(1, 10))
            dst_host_same_srv_rate = float(np.random.uniform(0.01, 0.08))
            dst_host_serror_rate = float(np.random.uniform(0.3, 0.7))
            label = 1

        elif cat == "Brute_Force_SSH":
            proto = "tcp"
            serv = "ssh"
            flag = np.random.choice(["SF", "REJ"], p=[0.7, 0.3])
            duration = float(np.random.uniform(1.0, 5.0))
            src_bytes = int(np.random.uniform(400, 1500)) # Credential exchange payloads
            dst_bytes = int(np.random.uniform(200, 800))
            count = int(np.random.randint(40, 120)) # High recurring connection attempts
            srv_count = count
            serror_rate = float(np.random.uniform(0.05, 0.25))
            same_srv_rate = 1.0 # Always targeted to SSH port 22
            diff_srv_rate = 0.0
            dst_host_count = int(np.random.randint(50, 150))
            dst_host_srv_count = dst_host_count
            dst_host_same_srv_rate = 1.0
            dst_host_serror_rate = float(np.random.uniform(0.05, 0.3))
            label = 1

        elif cat == "Web_Attack_SQLi":
            proto = "tcp"
            serv = "http"
            flag = "SF"
            duration = float(np.random.uniform(0.5, 3.5))
            src_bytes = int(np.random.uniform(2500, 8000)) # Large SQL query string / payload injection
            dst_bytes = int(np.random.uniform(500, 4000))
            count = int(np.random.randint(5, 25))
            srv_count = count
            serror_rate = float(np.random.uniform(0.0, 0.1))
            same_srv_rate = 1.0
            diff_srv_rate = 0.0
            dst_host_count = int(np.random.randint(20, 80))
            dst_host_srv_count = dst_host_count
            dst_host_same_srv_rate = 1.0
            dst_host_serror_rate = 0.0
            label = 1

        elif cat == "Botnet_Infiltration":
            proto = np.random.choice(["tcp", "udp"], p=[0.6, 0.4])
            serv = "other"
            flag = np.random.choice(["SF", "S0"], p=[0.6, 0.4])
            duration = float(np.random.uniform(10.0, 60.0)) # Periodic beaconing / persistence
            src_bytes = int(np.random.uniform(128, 512)) # Periodic small heartbeat
            dst_bytes = int(np.random.uniform(64, 256))
            count = int(np.random.randint(10, 45))
            srv_count = int(np.random.randint(5, 20))
            serror_rate = float(np.random.uniform(0.1, 0.4))
            same_srv_rate = float(np.random.uniform(0.4, 0.8))
            diff_srv_rate = float(np.random.uniform(0.2, 0.6))
            dst_host_count = int(np.random.randint(15, 60))
            dst_host_srv_count = int(np.random.randint(5, 30))
            dst_host_same_srv_rate = float(np.random.uniform(0.3, 0.7))
            dst_host_serror_rate = float(np.random.uniform(0.1, 0.3))
            label = 1

        data.append({
            "duration": round(duration, 4),
            "protocol_type": proto,
            "service": serv,
            "flag": flag,
            "src_bytes": src_bytes,
            "dst_bytes": dst_bytes,
            "count": count,
            "srv_count": srv_count,
            "serror_rate": round(serror_rate, 4),
            "same_srv_rate": round(same_srv_rate, 4),
            "diff_srv_rate": round(diff_srv_rate, 4),
            "dst_host_count": dst_host_count,
            "dst_host_srv_count": dst_host_srv_count,
            "dst_host_same_srv_rate": round(dst_host_same_srv_rate, 4),
            "dst_host_serror_rate": round(dst_host_serror_rate, 4),
            "attack_type": cat,
            "label": label
        })

    df = pd.DataFrame(data)
    return df

if __name__ == "__main__":
    output_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
    os.makedirs(output_dir, exist_ok=True)
    out_file = os.path.join(output_dir, "network_traffic.csv")
    print(f"Generating realistic cyber threat telemetry dataset...")
    df = generate_network_traffic_dataset(num_samples=15000)
    df.to_csv(out_file, index=False)
    print(f"Dataset successfully created at: {out_file}")
    print(f"Total samples: {len(df)}")
    print("Class Breakdown:")
    print(df["attack_type"].value_counts())
