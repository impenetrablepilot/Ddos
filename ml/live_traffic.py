"""
live_traffic.py
----------------
Simulates a live stream of network flow samples (as if captured off the
wire in short time windows). Used by the Flask app to demonstrate the
detection pipeline without needing a real network capture. Uses the same
generators as data/generate_traffic.py so the statistical signature
matches what the models were trained on.
"""
import random
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "data"))
from generate_traffic import make_benign, make_syn_flood, make_udp_flood, make_http_flood  # noqa: E402
import numpy as np

_GENERATORS = {
    "benign": make_benign,
    "syn_flood": make_syn_flood,
    "udp_flood": make_udp_flood,
    "http_flood": make_http_flood,
}

_rng = np.random.default_rng()


def next_flow(force_label: str = None, source_id: str = None) -> dict:
    """Generate a single simulated flow sample.

    force_label: if provided, generate that traffic type; otherwise
                 sampled randomly (weighted toward benign, like real traffic).
    source_id:   a synthetic identifier for the "attacker"/client
                 (used by the mitigation contract to track repeat offenses).
    """
    if force_label is None:
        force_label = random.choices(
            population=["benign", "syn_flood", "udp_flood", "http_flood"],
            weights=[0.7, 0.1, 0.1, 0.1],
            k=1,
        )[0]

    df = _GENERATORS[force_label](1, _rng)
    row = df.iloc[0].to_dict()
    row.pop("label", None)

    if source_id is None:
        if force_label == "benign":
            source_id = f"user-{random.randint(1, 500)}"
        else:
            source_id = f"botnet-{random.randint(1, 25)}"

    row["source_id"] = source_id
    row["true_label"] = force_label
    return row
