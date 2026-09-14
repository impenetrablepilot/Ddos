"""
train_model.py
---------------
Trains two models on the traffic dataset:

1. RandomForestClassifier  -> supervised multi-class traffic classification
   (benign / syn_flood / udp_flood / http_flood), used as the primary
   detector.
2. IsolationForest          -> unsupervised anomaly detector trained only
   on benign traffic, used as a secondary check that can flag novel /
   unseen attack patterns the classifier wasn't trained on.

Both models are saved to ../models/ so the Flask app and detector.py can
load them without retraining.

Run:
    python train_model.py --data ../data/dataset.csv
"""
import argparse
import json
import os

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

FEATURES = [
    "packet_rate", "byte_rate", "avg_packet_size", "flow_duration",
    "syn_ratio", "src_ip_entropy", "unique_src_ips",
    "protocol_udp_frac", "protocol_tcp_frac", "protocol_http_frac",
    "avg_inter_arrival",
]

MODELS_DIR = os.path.join(os.path.dirname(__file__), "..", "models")


def main(data_path):
    os.makedirs(MODELS_DIR, exist_ok=True)
    df = pd.read_csv(data_path)

    X = df[FEATURES]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    scaler = StandardScaler().fit(X_train)
    X_train_s = scaler.transform(X_train)
    X_test_s = scaler.transform(X_test)

    # ---- Supervised classifier ----
    clf = RandomForestClassifier(
        n_estimators=200, max_depth=12, random_state=42, n_jobs=-1
    )
    clf.fit(X_train_s, y_train)
    preds = clf.predict(X_test_s)

    report = classification_report(y_test, preds, output_dict=True)
    cm = confusion_matrix(y_test, preds, labels=clf.classes_)

    print("=== Random Forest classification report ===")
    print(classification_report(y_test, preds))
    print("=== Confusion matrix ===")
    print(pd.DataFrame(cm, index=clf.classes_, columns=clf.classes_))

    # ---- Unsupervised anomaly detector (trained on benign only) ----
    benign_mask = y_train == "benign"
    iso = IsolationForest(
        n_estimators=200, contamination=0.05, random_state=42
    )
    iso.fit(X_train_s[benign_mask.values])

    # Feature importances (for the report / dashboard)
    importances = dict(zip(FEATURES, clf.feature_importances_.tolist()))

    joblib.dump(clf, os.path.join(MODELS_DIR, "rf_classifier.joblib"))
    joblib.dump(iso, os.path.join(MODELS_DIR, "isolation_forest.joblib"))
    joblib.dump(scaler, os.path.join(MODELS_DIR, "scaler.joblib"))
    with open(os.path.join(MODELS_DIR, "metrics.json"), "w") as f:
        json.dump({
            "classification_report": report,
            "confusion_matrix": cm.tolist(),
            "classes": clf.classes_.tolist(),
            "feature_importances": importances,
        }, f, indent=2)

    print(f"\nSaved models to {os.path.abspath(MODELS_DIR)}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=os.path.join(os.path.dirname(__file__), "..", "data", "dataset.csv"))
    args = ap.parse_args()
    main(args.data)
