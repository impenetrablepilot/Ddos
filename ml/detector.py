"""
detector.py
-----------
Loads the trained ML models and exposes a single classify() function
that the Flask app (and any future real traffic-capture integration)
calls for each incoming flow sample.
"""
import os
import joblib
import numpy as np
import pandas as pd

FEATURES = [
    "packet_rate", "byte_rate", "avg_packet_size", "flow_duration",
    "syn_ratio", "src_ip_entropy", "unique_src_ips",
    "protocol_udp_frac", "protocol_tcp_frac", "protocol_http_frac",
    "avg_inter_arrival",
]

MODELS_DIR = os.path.join(os.path.dirname(__file__), "..", "models")


class Detector:
    def __init__(self):
        self.clf = joblib.load(os.path.join(MODELS_DIR, "rf_classifier.joblib"))
        self.iso = joblib.load(os.path.join(MODELS_DIR, "isolation_forest.joblib"))
        self.scaler = joblib.load(os.path.join(MODELS_DIR, "scaler.joblib"))

    def classify(self, flow: dict) -> dict:
        x = pd.DataFrame([[flow[f] for f in FEATURES]], columns=FEATURES)
        x_scaled = self.scaler.transform(x)

        proba = self.clf.predict_proba(x_scaled)[0]
        classes = self.clf.classes_
        top_idx = int(np.argmax(proba))
        predicted_label = classes[top_idx]
        confidence = float(proba[top_idx])

        anomaly_flag = bool(self.iso.predict(x_scaled)[0] == -1)  # -1 = anomaly

        return {
            "predicted_label": predicted_label,
            "confidence": confidence,
            "class_probabilities": dict(zip(classes.tolist(), proba.tolist())),
            "anomaly_flag": anomaly_flag,
        }
