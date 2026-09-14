"""
protected_site.py
------------------
A small, self-owned demo website ("ShieldChain Mini-Shop") that stands in
for a real protected server. This is the piece that lets the project
demonstrate REAL request monitoring and REAL enforcement, rather than
only classifying simulated traffic.

How it's wired in (see app.py):
  - Every request to a /shop/* route passes through `before_request`,
    which checks the real, in-memory blacklist FIRST (real enforcement --
    a blacklisted source gets a 429 response and never reaches the page).
  - If not blacklisted, RequestMonitor records the real request and
    returns a real feature vector (see request_monitor.py).
  - That feature vector is classified by the SAME trained model used
    elsewhere in the project (ml/detector.py) -- no separate model.
  - The SAME mitigation rule engine (blockchain/smart_contract.py) and
    the SAME blockchain ledger (blockchain/blockchain.py) used for the
    simulated-traffic dashboard are reused here, so a real detection on
    the demo shop and a simulated detection from the dashboard both show
    up in one unified ledger and feed.

To generate real test traffic against this (on your own deployed URL
only -- never point load-testing tools at a site you don't own):
    ab -n 200 -c 20 https://your-app.onrender.com/shop/
    hey -n 200 -c 20 https://your-app.onrender.com/shop/
"""
from flask import Blueprint, request, jsonify, render_template_string

protected_site = Blueprint("protected_site", __name__)

# In-memory demo catalog -- the "real" content being protected.
PRODUCTS = [
    {"id": 1, "name": "ShieldChain T-Shirt", "price": "$19.99"},
    {"id": 2, "name": "Blockchain Sticker Pack", "price": "$4.99"},
    {"id": 3, "name": "Proof-of-Work Mug", "price": "$12.50"},
]

SHOP_TEMPLATE = """
<!DOCTYPE html>
<html><head><title>ShieldChain Mini-Shop (demo protected site)</title>
<style>
  body { font-family: sans-serif; background:#0a0d12; color:#e6e9ef; padding: 40px; }
  .card { background:#10141b; border:1px solid #1e2530; border-radius:8px; padding:16px; margin-bottom:12px; max-width:400px; }
  h1 { color:#3ec9c9; }
  .price { color:#4caf7d; font-weight:bold; }
  .note { color:#7a8494; font-size:13px; max-width:500px; }
</style>
</head><body>
  <h1>ShieldChain Mini-Shop</h1>
  <p class="note">This is a small, self-owned demo site used to generate and monitor
  <b>real</b> HTTP traffic for the ShieldChain project -- every request here is
  genuinely captured and classified, not simulated. See the main dashboard's
  "Real Traffic" panel for live detections.</p>
  {% for p in products %}
    <div class="card"><b>{{ p.name }}</b><br><span class="price">{{ p.price }}</span></div>
  {% endfor %}
</body></html>
"""

BLOCKED_TEMPLATE = """
<!DOCTYPE html>
<html><head><title>Access Restricted</title>
<style>body{font-family:sans-serif;background:#0a0d12;color:#e2554f;padding:60px;text-align:center;}</style>
</head><body>
  <h1>429 -- Access Temporarily Restricted</h1>
  <p>Your source has been flagged by ShieldChain's real-time traffic monitor
  for exceeding normal request patterns and is currently rate-limited.</p>
</body></html>
"""


def register_shop_routes(app, monitor, detector, contract, chain, on_event=None):
    """Wire the demo shop's routes into the main Flask app, sharing the
    same monitor/detector/contract/chain instances the dashboard uses."""

    def get_source_id():
        # Respect X-Forwarded-For since Render sits behind a proxy;
        # fall back to remote_addr for local testing.
        fwd = request.headers.get("X-Forwarded-For", "")
        return fwd.split(",")[0].strip() if fwd else (request.remote_addr or "unknown")

    @app.before_request
    def _shop_gate():
        if not request.path.startswith("/shop"):
            return None  # not a protected route, let it through untouched

        source_id = get_source_id()
        if contract.is_blacklisted(source_id):
            return render_template_string(BLOCKED_TEMPLATE), 429
        return None

    @app.route("/shop/")
    @app.route("/shop")
    def shop_index():
        import time
        source_id = get_source_id()
        request_bytes = len(request.headers.get("User-Agent", "")) + 200  # rough real request size proxy

        features = monitor.record_and_extract(source_id, request_bytes)
        result = detector.classify(features)

        event = {
            "source_id": source_id,
            "predicted_label": result["predicted_label"],
            "confidence": result["confidence"],
            "real_traffic": True,
            "timestamp": time.time(),
        }
        mitigation = contract.evaluate(event)
        event["mitigation_action"] = mitigation["action"]
        event["mitigation_reason"] = mitigation["reason"]

        if mitigation["action"] != "allow":
            block = chain.add_block({
                "source_id": source_id,
                "predicted_label": event["predicted_label"],
                "confidence": round(event["confidence"], 4),
                "action": mitigation["action"],
                "reason": mitigation["reason"],
                "real_traffic": True,
            })
            event["block_index"] = block.index
            event["block_hash"] = block.hash

        if on_event:
            on_event(event)

        return render_template_string(SHOP_TEMPLATE, products=PRODUCTS)

    return app
