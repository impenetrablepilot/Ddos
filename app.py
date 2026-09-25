"""
app.py
------
Flask dashboard for the ML + Blockchain DDoS mitigation demo.

Endpoints:
  GET  /                 -> dashboard UI
  POST /api/simulate     -> generate N SIMULATED traffic flows, run them
                             through the ML detector + smart contract,
                             append non-benign events to the blockchain
  GET  /api/state        -> current dashboard state (recent flows, ledger,
                             blacklist, chain validity) -- includes both
                             simulated and real traffic
  POST /api/reset        -> reset the in-memory demo state
  GET  /shop, /shop/...  -> a small, REAL, self-owned demo website whose
                             genuine incoming traffic is monitored,
                             classified, and enforced against using the
                             same ML/blockchain pipeline (see
                             request_monitor.py and protected_site.py)

Run:
    python app.py
Then open http://localhost:5000 for the dashboard, or http://localhost:5000/shop
for the real, monitored demo site.
"""
import os
import sys
import time

from flask import Flask, jsonify, render_template, request

sys.path.append(os.path.join(os.path.dirname(__file__), "ml"))
sys.path.append(os.path.join(os.path.dirname(__file__), "blockchain"))

from detector import Detector          # noqa: E402
from live_traffic import next_flow     # noqa: E402
from request_monitor import RequestMonitor  # noqa: E402
from safe_online_learner import SafeOnlineLearner  # noqa: E402
from blockchain import Blockchain      # noqa: E402
from smart_contract import MitigationContract  # noqa: E402
from protected_site import protected_site, register_shop_routes  # noqa: E402
import joblib
import pandas as pd

app = Flask(__name__)

# Shared secret checked against the X-Shared-Key header on /api/network_event,
# so an external network_monitor.py instance (running with root on a machine
# you control) can report real packet-layer detections here, but random
# internet traffic can't forge entries into your blockchain ledger. Set this
# via an environment variable in production; the default is only for local
# testing.
NETWORK_MONITOR_KEY = os.environ.get("NETWORK_MONITOR_KEY", "change-me-in-production")

detector = Detector()
chain = Blockchain()
contract = MitigationContract()
monitor = RequestMonitor()

# Safe, one-directional online learner (see ml/safe_online_learner.py for
# the full design and the poisoning defenses it implements). Consulted
# only to ADD detections on top of the baseline model, never to override
# a baseline detection into "allow." It only ever learns from sources the
# existing smart_contract.py escalation has ALREADY independently
# blacklisted -- never from a raw, unconfirmed classification.
_online_scaler = joblib.load(os.path.join(os.path.dirname(__file__), "models", "scaler.joblib"))
_dataset_path = os.path.join(os.path.dirname(__file__), "data", "dataset.csv")
_online_validation_set = None
if os.path.exists(_dataset_path):
    _val_df = pd.read_csv(_dataset_path).sample(min(500, 500), random_state=1)
    from safe_online_learner import FEATURES as _OL_FEATURES
    _online_validation_set = (_val_df[_OL_FEATURES].values, _val_df["label"].values)
online_learner = SafeOnlineLearner(baseline_scaler=_online_scaler, validation_set=_online_validation_set)
online_learner.load_from_disk()  # restore any real, previously learned attack knowledge

recent_flows = []   # rolling log of recent flow classifications (simulated AND real)
MAX_RECENT = 60

stats = {
    "requests_received": 0,     # every real /shop request, incremented in protected_site.py's gate
    "blocked_fastpath": 0,      # real requests rejected instantly for an already-blacklisted source
    "action_counts": {"allow": 0, "monitor": 0, "rate_limit": 0, "challenge": 0, "blacklist": 0},
}


def _record_event(event):
    """Shared by both the simulated-traffic path and the real-traffic
    (/shop) path, so both show up in the same dashboard feed/ledger/stats.

    This is also the single point where a CONFIRMED blacklist (the
    existing, independent 2-strike escalation in smart_contract.py) is
    offered to the safe online learner -- see ml/safe_online_learner.py
    for why only blacklist-confirmed samples are ever used to teach it,
    and why it can never be taught a 'benign' label from live traffic.
    """
    features = event.pop("_features", None)
    if event.get("mitigation_action") == "blacklist" and features is not None:
        online_learner.submit_confirmed_attack(
            source_id=event["source_id"],
            features=features,
            label=event["predicted_label"],
            confirmed_by_blacklist=True,
            chain=chain,
        )

    recent_flows.append(event)
    del recent_flows[:-MAX_RECENT]
    action = event.get("mitigation_action")
    if action in stats["action_counts"]:
        stats["action_counts"][action] += 1


register_shop_routes(app, monitor, detector, contract, chain, on_event=_record_event, stats=stats, online_learner=online_learner)


def process_one_flow(force_label=None, source_id=None):
    flow = next_flow(force_label=force_label, source_id=source_id)
    features = {k: v for k, v in flow.items() if k not in ("source_id", "true_label")}

    result = detector.classify(features)

    # Same "escalate-only" online learner consultation as the real /nandhu
    # path -- see ml/safe_online_learner.py and protected_site.py.
    if result["predicted_label"] == "benign":
        online_label = online_learner.consult(features)
        if online_label:
            result = dict(result)
            result["predicted_label"] = online_label
            result["confidence"] = max(result["confidence"], 0.75)
            result["online_learner_override"] = True

    event = {
        "source_id": flow["source_id"],
        "true_label": flow["true_label"],
        "predicted_label": result["predicted_label"],
        "confidence": result["confidence"],
        "anomaly_flag": result["anomaly_flag"],
        "real_traffic": False,
        "timestamp": time.time(),
        "_features": features,  # internal only; stripped before going to the dashboard/ledger
    }

    mitigation = contract.evaluate(event)
    event["mitigation_action"] = mitigation["action"]
    event["mitigation_reason"] = mitigation["reason"]

    # Only non-benign / non-allow actions go on the immutable ledger,
    # mirroring the "don't spend gas logging benign traffic" design
    # in smart_contract.sol.
    if mitigation["action"] != "allow":
        block = chain.add_block({
            "source_id": event["source_id"],
            "predicted_label": event["predicted_label"],
            "confidence": round(event["confidence"], 4),
            "action": mitigation["action"],
            "reason": mitigation["reason"],
        })
        event["block_index"] = block.index
        event["block_hash"] = block.hash

    _record_event(event)
    return event


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/simulate", methods=["POST"])
def simulate():
    payload = request.get_json(silent=True) or {}
    count = int(payload.get("count", 1))
    force_label = payload.get("label")  # optional: "benign" | "syn_flood" | "udp_flood" | "http_flood"
    source_id = payload.get("source_id")

    count = max(1, min(count, 200))
    results = [process_one_flow(force_label=force_label, source_id=source_id) for _ in range(count)]
    return jsonify({"results": results, "chain_valid": chain.is_valid()})


@app.route("/api/network_event", methods=["POST"])
def network_event():
    """Receives a CONFIRMED network/packet-layer detection from an
    external network_monitor.py instance (see that file's docstring) --
    running with root on a machine you control, doing real packet
    capture and real SYN-ratio/protocol measurement that this web
    process itself cannot perform. Authenticated with a shared secret
    so this can't be spoofed by arbitrary internet traffic.
    """
    key = request.headers.get("X-Shared-Key", "")
    if key != NETWORK_MONITOR_KEY:
        return jsonify({"error": "invalid key"}), 403

    payload = request.get_json(silent=True) or {}
    required = {"source_id", "predicted_label", "confidence", "mitigation_action"}
    if not required.issubset(payload):
        return jsonify({"error": f"missing fields, need {required}"}), 400

    event = {
        "source_id": payload["source_id"],
        "predicted_label": payload["predicted_label"],
        "confidence": float(payload["confidence"]),
        "mitigation_action": payload["mitigation_action"],
        "mitigation_reason": payload.get("reason", "Confirmed by network-layer packet monitor."),
        "real_traffic": True,
        "layer": "network",  # distinguishes this from HTTP-layer ("layer" absent/"http") and simulated traffic
        "timestamp": time.time(),
    }

    if event["mitigation_action"] != "allow":
        block = chain.add_block({
            "source_id": event["source_id"],
            "predicted_label": event["predicted_label"],
            "confidence": round(event["confidence"], 4),
            "action": event["mitigation_action"],
            "reason": event["mitigation_reason"],
            "real_traffic": True,
            "layer": "network",
        })
        event["block_index"] = block.index
        event["block_hash"] = block.hash

    _record_event(event)
    return jsonify({"status": "recorded", "chain_valid": chain.is_valid()})


@app.route("/api/state")
def state():
    blacklisted = {sid: n for sid, n in contract._strikes.items() if sid in contract._blacklisted}
    return jsonify({
        "recent_flows": list(reversed(recent_flows)),
        "chain": chain.to_list(),
        "chain_valid": chain.is_valid(),
        "chain_length": len(chain.chain),
        "blacklisted_sources": blacklisted,
        "stats": stats,
        "active_sources": monitor.active_sources(within_seconds=10.0),
        "online_learner": online_learner.stats(),
    })


@app.route("/api/reset", methods=["POST"])
def reset():
    """Resets DEMO/SESSION state only: the blockchain ledger, the
    blacklist, the request-history window, and displayed stats.

    Deliberately does NOT touch online_learner. That component holds
    real, accumulated attack knowledge (see ml/safe_online_learner.py) --
    if a source was genuinely confirmed as an attacker and taught to the
    online learner, clicking a demo "Reset" button should not make the
    system forget that and have to rediscover the same real attacker
    from zero again. Use /api/reset_online_learner (below) if you
    specifically want to wipe that too, e.g. for a controlled test.
    """
    global recent_flows
    chain.reset()
    contract.reset()
    monitor.__init__()  # clear all in-memory request-history state
    recent_flows = []
    stats["requests_received"] = 0
    stats["blocked_fastpath"] = 0
    for k in stats["action_counts"]:
        stats["action_counts"][k] = 0
    return jsonify({"status": "reset"})


@app.route("/api/reset_online_learner", methods=["POST"])
def reset_online_learner():
    """Separate, explicit endpoint to wipe the online learner's learned
    knowledge -- deliberately NOT part of /api/reset (see its docstring).
    Also deletes the on-disk saved state, so this wipe is permanent
    rather than being silently restored on the next server restart.
    """
    online_learner.reset()
    state_path = online_learner._default_state_path()
    if os.path.exists(state_path):
        os.remove(state_path)
    return jsonify({"status": "online learner reset (in memory and on disk)"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug)
