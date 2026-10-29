"""
CyberSage AI - Machine Learning Model Training Engine.

Trains a Random Forest Classifier and Risk Regressor on endpoint
security configuration parameters to predict:
1. System Breach Risk Level (LOW, MEDIUM, CRITICAL)
2. Threat / Compromise Probability (0.0 to 1.0)
3. Key Exploit Vulnerability Drivers based on Feature Importances.
"""

import os
import csv
import json
import joblib
from datetime import datetime, timezone
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, RandomForestRegressor
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

FEATURE_NAMES = [
    "firewall_enabled",
    "defender_realtime",
    "sig_freshness_days",
    "windows_update",
    "uac_enabled",
    "guest_disabled",
    "smb1_disabled",
    "rdp_nla_enforced",
    "restrict_anonymous",
    "pua_protection",
    "controlled_folder_access",
    "script_block_logging"
]

FEATURE_LABELS = {
    "firewall_enabled": "Windows Firewall Profiles",
    "defender_realtime": "Microsoft Defender Real-Time Protection",
    "sig_freshness_days": "Threat Definition Freshness",
    "windows_update": "Windows Update Service",
    "uac_enabled": "User Account Control (UAC)",
    "guest_disabled": "Guest Account Hardening",
    "smb1_disabled": "SMBv1 Legacy Protocol (WannaCry / MS17-010)",
    "rdp_nla_enforced": "Remote Desktop NLA (BlueKeep Mitigation)",
    "restrict_anonymous": "Anonymous SAM & Share Enumeration",
    "pua_protection": "Defender PUA Protection (Adware / Miners)",
    "controlled_folder_access": "Controlled Folder Access (Ransomware Guard)",
    "script_block_logging": "PowerShell Script Block Logging (Event ID 4104)"
}

def train():
    print("=" * 70)
    print("  CyberSage AI - Machine Learning Security Model Training Pipeline")
    print("=" * 70)

    dataset_path = "data/system_vulnerability_dataset.csv"
    if not os.path.exists(dataset_path):
        print(f"[*] Dataset not found at {dataset_path}. Generating dataset first...")
        from data.generate_dataset import generate_vulnerability_dataset
        generate_vulnerability_dataset(dataset_path, 5000)

    print(f"[*] Loading training dataset from {dataset_path}...")
    X_list = []
    y_class_list = []
    y_prob_list = []

    with open(dataset_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            features = [float(row[k]) for k in FEATURE_NAMES]
            X_list.append(features)
            y_class_list.append(row["risk_level"])
            y_prob_list.append(float(row["compromise_probability"]))

    X = np.array(X_list)
    y_class = np.array(y_class_list)
    y_prob = np.array(y_prob_list)

    total_samples = len(X)
    print(f"[+] Loaded {total_samples} security audit samples with {X.shape[1]} defensive features.")

    # Train / Test Split (80% Train, 20% Test)
    X_train, X_test, y_train_cls, y_test_cls, y_train_prob, y_test_prob = train_test_split(
        X, y_class, y_prob, test_size=0.20, random_state=42, stratify=y_class
    )

    print(f"[*] Splitting: {len(X_train)} Training samples | {len(X_test)} Testing samples.")
    print("[*] Training Random Forest Risk Classifier (100 Trees)...")

    clf = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42)
    clf.fit(X_train, y_train_cls)

    print("[*] Training Breach Probability Regressor...")
    reg = RandomForestRegressor(n_estimators=100, max_depth=12, random_state=42)
    reg.fit(X_train, y_train_prob)

    # Evaluate Model
    y_pred_cls = clf.predict(X_test)
    y_train_pred_cls = clf.predict(X_train)

    train_acc = accuracy_score(y_train_cls, y_train_pred_cls)
    test_acc = accuracy_score(y_test_cls, y_pred_cls)
    prec = precision_score(y_test_cls, y_pred_cls, average="weighted")
    rec = recall_score(y_test_cls, y_pred_cls, average="weighted")
    f1 = f1_score(y_test_cls, y_pred_cls, average="weighted")
    cm = confusion_matrix(y_test_cls, y_pred_cls, labels=["LOW", "MEDIUM", "CRITICAL"]).tolist()

    # Feature Importances
    importances = clf.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]
    ranked_features = []
    print("\n" + "=" * 70)
    print("  TOP PREDICTIVE EXPLOIT VULNERABILITIES (Feature Importance Weights):")
    print("=" * 70)
    for rank, idx in enumerate(sorted_idx, 1):
        feat_name = FEATURE_NAMES[idx]
        weight = float(importances[idx])
        label = FEATURE_LABELS[feat_name]
        ranked_features.append({
            "rank": rank,
            "feature": feat_name,
            "label": label,
            "importance": round(weight, 4),
            "percentage": round(weight * 100, 2)
        })
        print(f"  {rank:02d}. {label:<50} | Weight: {weight:.4f} ({weight * 100:.1f}%)")

    print("\n" + "=" * 70)
    print("  MODEL EVALUATION METRICS:")
    print("=" * 70)
    print(f"  [*] Training Set Accuracy : {train_acc * 100:.2f}%")
    print(f"  [*] Testing Set Accuracy  : {test_acc * 100:.2f}%")
    print(f"  [*] Weighted Precision    : {prec * 100:.2f}%")
    print(f"  [*] Weighted Recall       : {rec * 100:.2f}%")
    print(f"  [*] Weighted F1-Score     : {f1 * 100:.2f}%")
    print("=" * 70)

    # Save models
    os.makedirs("models", exist_ok=True)
    clf_path = "models/vulnerability_classifier.pkl"
    reg_path = "models/breach_risk_regressor.pkl"
    meta_path = "models/model_metadata.json"

    joblib.dump(clf, clf_path)
    joblib.dump(reg, reg_path)

    metadata = {
        "model_name": "CyberSage Random Forest Threat & Vulnerability Classifier",
        "algorithm": "Random Forest (Ensemble of 100 Decision Trees)",
        "features": FEATURE_NAMES,
        "feature_labels": FEATURE_LABELS,
        "total_samples": total_samples,
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "train_accuracy_pct": round(train_acc * 100, 2),
        "test_accuracy_pct": round(test_acc * 100, 2),
        "precision_pct": round(prec * 100, 2),
        "recall_pct": round(rec * 100, 2),
        "f1_score_pct": round(f1 * 100, 2),
        "confusion_matrix": cm,
        "ranked_features": ranked_features,
        "classes": ["LOW", "MEDIUM", "CRITICAL"],
        "trained_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    }

    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=4)

    print(f"\n[+] Saved trained model artifacts:")
    print(f"    - {clf_path}")
    print(f"    - {reg_path}")
    print(f"    - {meta_path}")
    print("\n[SUCCESS] Model training complete and ready for deployment!\n")
    return metadata

if __name__ == "__main__":
    train()
