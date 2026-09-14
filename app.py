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
from blockchain import Blockchain      # noqa: E402
from smart_contract import MitigationContract  # noqa: E402
from protected_site import protected_site, register_shop_routes  # noqa: E402

app = Flask(__name__)

detector = Detector()
chain = Blockchain()
contract = MitigationContract()
monitor = RequestMonitor()

recent_flows = []   # rolling log of recent flow classifications (simulated AND real)
MAX_RECENT = 60

stats = {
    "requests_received": 0,     # every real /shop request, incremented in protected_site.py's gate
    "blocked_fastpath": 0,      # real requests rejected instantly for an already-blacklisted source
    "action_counts": {"allow": 0, "monitor": 0, "rate_limit": 0, "challenge": 0, "blacklist": 0},
}


def _record_event(event):
    """Shared by both the simulated-traffic path and the real-traffic
    (/shop) path, so both show up in the same dashboard feed/ledger/stats."""
    recent_flows.append(event)
    del recent_flows[:-MAX_RECENT]
    action = event.get("mitigation_action")
    if action in stats["action_counts"]:
        stats["action_counts"][action] += 1


register_shop_routes(app, monitor, detector, contract, chain, on_event=_record_event, stats=stats)


def process_one_flow(force_label=None, source_id=None):
    flow = next_flow(force_label=force_label, source_id=source_id)
    features = {k: v for k, v in flow.items() if k not in ("source_id", "true_label")}

    result = detector.classify(features)
    event = {
        "source_id": flow["source_id"],
        "true_label": flow["true_label"],
        "predicted_label": result["predicted_label"],
        "confidence": result["confidence"],
        "anomaly_flag": result["anomaly_flag"],
        "real_traffic": False,
        "timestamp": time.time(),
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
    })


@app.route("/api/reset", methods=["POST"])
def reset():
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


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug)
