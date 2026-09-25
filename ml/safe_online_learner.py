"""
safe_online_learner.py
-----------------------
Adds genuine online/continuous learning to ShieldChain, specifically
designed so the classic poisoning attack ("teach the system my attack
traffic is normal") is structurally impossible, not just discouraged.

THE CORE IDEA: ASYMMETRIC, ONE-DIRECTIONAL LEARNING
----------------------------------------------------
The online learner is only ever allowed to make the system MORE
suspicious of a pattern. It can never make the system LESS suspicious.
Concretely:

  1. It NEVER trains on "benign" labels from live traffic. An attacker
     sending traffic and hoping the system learns "this is normal" has
     no mechanism to exploit, because normal-traffic updates simply
     don't happen here -- benign behavior is defined once, offline, by
     the original vetted training data (data/generate_traffic.py) and
     never touched again.

  2. It only trains on samples that have been INDEPENDENTLY CONFIRMED
     as attacks by the existing rule-based escalation path (i.e., a
     source that was already blacklisted by smart_contract.py through
     the normal 2-strike process) -- not from a single classification.
     This means poisoning this learner requires successfully triggering
     your own blacklist against yourself first, which is self-defeating
     for an attacker.

  3. Per-source contribution is capped (MAX_SAMPLES_PER_SOURCE). One
     attacker, however persistent, can only ever contribute a bounded
     amount of "this pattern is an attack" signal -- they cannot flood
     the learner with volume to dominate its gradient.

  4. The online model can only ADD detections on top of the frozen,
     offline-validated baseline model (ml/detector.py) -- it is
     consulted only when the baseline says "benign," to catch NEW
     attack patterns the baseline was never trained on. It is never
     given the power to override a baseline "attack" call into "allow."

  5. Every accepted update is logged to the blockchain (a hash of the
     feature vector, the source, and a timestamp) via the SAME ledger
     used elsewhere in this project, so the full history of what the
     online learner was ever taught is permanently auditable.

  6. The learner is periodically evaluated against a FROZEN validation
     set that is never used for training. If accuracy on that fixed set
     ever drops, the learner is automatically rolled back to its last
     known-good checkpoint.

This still delivers real value: the system can learn to recognize a
genuinely new attack *pattern* it was never trained on, the moment one
occurrence of it gets confirmed through the normal escalation path --
without ever being able to be taught that an attack is safe.
"""
import hashlib
import json
import os
import pickle
import time
from collections import defaultdict

import numpy as np
import pandas as pd
from sklearn.linear_model import SGDClassifier
from sklearn.preprocessing import StandardScaler

FEATURES = [
    "packet_rate", "byte_rate", "avg_packet_size", "flow_duration",
    "syn_ratio", "src_ip_entropy", "unique_src_ips",
    "protocol_udp_frac", "protocol_tcp_frac", "protocol_http_frac",
    "avg_inter_arrival",
]

MAX_SAMPLES_PER_SOURCE = 5          # hard cap: one source can never teach more than this
MIN_TOTAL_SAMPLES_BEFORE_CONSULT = 8  # don't trust this model's opinion until it has seen a few diverse confirmed examples
CHECKPOINT_DIR = os.path.join(os.path.dirname(__file__), "..", "models", "online_checkpoints")


class SafeOnlineLearner:
    def __init__(self, baseline_scaler: StandardScaler, validation_set=None):
        """
        baseline_scaler: the SAME scaler used by the frozen baseline model,
                          so feature space is consistent between the two.
        validation_set:  (X, y) tuple, held out and NEVER trained on, used
                          to detect if an update degraded the online model.
        """
        self.baseline_scaler = baseline_scaler
        self.validation_set = validation_set
        self.model = SGDClassifier(loss="log_loss", random_state=42)
        self._initialized = False
        self._per_source_count = defaultdict(int)
        self._update_log = []          # local mirror of what's on-chain
        self._last_good_checkpoint = None
        self._best_val_accuracy = -1.0
        os.makedirs(CHECKPOINT_DIR, exist_ok=True)

    # ---- the one and only way new data reaches this model ----
    def submit_confirmed_attack(self, source_id: str, features: dict, label: str,
                                 confirmed_by_blacklist: bool, chain=None) -> dict:
        """
        The ONLY entry point for teaching this model something new.
        Returns a dict explaining what happened (accepted / rejected + why).

        `confirmed_by_blacklist` must be True -- meaning smart_contract.py's
        normal escalation logic has ALREADY independently blacklisted this
        source through its own 2-strike process. This function does not
        trust a single classification; it trusts an already-completed
        independent decision.
        """
        if not confirmed_by_blacklist:
            return self._reject("not independently confirmed by blacklist escalation")

        if label == "benign":
            # Structurally unreachable in normal use (blacklist implies
            # non-benign), but guarded explicitly anyway: this model must
            # NEVER be able to learn a new "benign" example from live
            # traffic, under any circumstance.
            return self._reject("refusing to learn a 'benign' label from live traffic (by design)")

        if self._per_source_count[source_id] >= MAX_SAMPLES_PER_SOURCE:
            return self._reject(f"source {source_id} has already reached its {MAX_SAMPLES_PER_SOURCE}-sample training cap")

        x = pd.DataFrame([[features[f] for f in FEATURES]], columns=FEATURES)
        x_scaled = self.baseline_scaler.transform(x)

        if not self._initialized:
            # SGDClassifier needs all classes declared on first partial_fit
            self.model.partial_fit(x_scaled, [label], classes=["benign", "http_flood", "syn_flood", "udp_flood"])
            self._initialized = True
        else:
            self.model.partial_fit(x_scaled, [label])

        self._per_source_count[source_id] += 1

        # Immutable audit trail: log a hash of what was learned, not the
        # raw feature vector, keeping this consistent with the project's
        # existing privacy-conscious blockchain logging elsewhere.
        feature_hash = hashlib.sha256(json.dumps(features, sort_keys=True).encode()).hexdigest()
        entry = {
            "source_id": source_id, "label": label, "feature_hash": feature_hash,
            "timestamp": time.time(), "sample_number_for_source": self._per_source_count[source_id],
        }
        self._update_log.append(entry)
        if chain is not None:
            chain.add_block({"type": "online_learning_update", **entry})

        # Re-validate against the frozen validation set after every update;
        # roll back immediately if this update made things worse.
        if self.validation_set is not None:
            acc = self._validate()
            if acc < self._best_val_accuracy - 0.01:  # small tolerance for noise
                self._rollback()
                return self._reject(f"update degraded validation accuracy ({acc:.3f} < best {self._best_val_accuracy:.3f}) -- rolled back")
            if acc >= self._best_val_accuracy:
                self._best_val_accuracy = acc
                self._checkpoint()

        self.save_to_disk()  # persist immediately: this is real learned knowledge, not session state
        return {"accepted": True, "reason": "learned new confirmed-attack pattern", "log_entry": entry}

    def _reject(self, reason: str) -> dict:
        return {"accepted": False, "reason": reason}

    # ---- consulted only as a secondary opinion, never a veto over the baseline ----
    def consult(self, features: dict):
        """Returns a predicted label if this model is initialized,
        sufficiently trained, and confident, else None. Callers should
        only use this to escalate a baseline 'benign' verdict -- never to
        downgrade a baseline 'attack' verdict (see module docstring,
        point 4)."""
        if not self._initialized or len(self._update_log) < MIN_TOTAL_SAMPLES_BEFORE_CONSULT:
            return None
        x = pd.DataFrame([[features[f] for f in FEATURES]], columns=FEATURES)
        x_scaled = self.baseline_scaler.transform(x)
        pred = self.model.predict(x_scaled)[0]
        if pred == "benign":
            return None
        return pred

    def _validate(self) -> float:
        X_val, y_val = self.validation_set
        X_val_df = pd.DataFrame(X_val, columns=FEATURES) if not isinstance(X_val, pd.DataFrame) else X_val
        X_val_scaled = self.baseline_scaler.transform(X_val_df)
        preds = self.model.predict(X_val_scaled)
        return float(np.mean(preds == y_val))

    def _checkpoint(self):
        self._last_good_checkpoint = pickle.dumps(self.model)

    def _rollback(self):
        if self._last_good_checkpoint is not None:
            self.model = pickle.loads(self._last_good_checkpoint)

    def stats(self) -> dict:
        return {
            "initialized": self._initialized,
            "ready_to_consult": self._initialized and len(self._update_log) >= MIN_TOTAL_SAMPLES_BEFORE_CONSULT,
            "samples_needed_before_consult": max(0, MIN_TOTAL_SAMPLES_BEFORE_CONSULT - len(self._update_log)),
            "total_updates_accepted": len(self._update_log),
            "unique_sources_contributed": len(self._per_source_count),
            "best_validation_accuracy": self._best_val_accuracy,
            "per_source_counts": dict(self._per_source_count),
        }

    # ---- persistence: learned knowledge should survive a demo Reset and,
    # as far as the underlying disk allows, a server restart. This is
    # DELIBERATELY separate from reset() below -- clearing the dashboard's
    # session state (blockchain, feed, stats) must never silently erase
    # real, accumulated attack knowledge. ----
    def save_to_disk(self, path: str = None):
        path = path or self._default_state_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        state = {
            "model": self.model, "initialized": self._initialized,
            "per_source_count": dict(self._per_source_count),
            "update_log": self._update_log,
            "last_good_checkpoint": self._last_good_checkpoint,
            "best_val_accuracy": self._best_val_accuracy,
        }
        with open(path, "wb") as f:
            pickle.dump(state, f)

    def load_from_disk(self, path: str = None) -> bool:
        path = path or self._default_state_path()
        if not os.path.exists(path):
            return False
        with open(path, "rb") as f:
            state = pickle.load(f)
        self.model = state["model"]
        self._initialized = state["initialized"]
        self._per_source_count = defaultdict(int, state["per_source_count"])
        self._update_log = state["update_log"]
        self._last_good_checkpoint = state["last_good_checkpoint"]
        self._best_val_accuracy = state["best_val_accuracy"]
        return True

    @staticmethod
    def _default_state_path() -> str:
        return os.path.join(CHECKPOINT_DIR, "learner_state.pkl")

    def reset(self):
        """Reinitialize to a blank, untrained state, IN MEMORY ONLY.

        Deliberately does NOT delete any saved state on disk, and is
        deliberately NOT called by the dashboard's main /api/reset --
        clearing demo/session state must never silently erase real,
        accumulated attack knowledge. This method exists for genuine,
        deliberate testing/research use (e.g. wiping the learner to
        re-run an evaluation from a blank slate); a caller that wants
        the wipe to be permanent should also explicitly delete the
        on-disk state file."""
        self.model = SGDClassifier(loss="log_loss", random_state=42)
        self._initialized = False
        self._per_source_count = defaultdict(int)
        self._update_log = []
        self._last_good_checkpoint = None
        self._best_val_accuracy = -1.0
