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
from request_monitor import rate_heuristic_label

protected_site = Blueprint("protected_site", __name__)

# In-memory demo content -- the "real" content being protected. Reskinned
# as a personal profile page rather than a shop; the monitoring and
# enforcement logic below is completely unaffected by this -- it protects
# whatever content this route serves, regardless of what that content is.
PROFILE_LINKS = [
    {"label": "Instagram", "url": "https://www.instagram.com/nandhu_rahul_g", "icon": "📷"},
]

SHOP_TEMPLATE = """
<!DOCTYPE html>
<html><head><title>Nandhu Rahul G (ShieldChain-protected page)</title>
<style>
  body { font-family: sans-serif; background:#0a0d12; color:#e6e9ef; padding: 40px; display:flex; justify-content:center; }
  .profile-wrap { max-width: 480px; width: 100%; text-align: center; }
  .avatar {
    width: 96px; height: 96px; border-radius: 50%; margin: 0 auto 16px;
    background: linear-gradient(135deg, #3ec9c9, #8a7cf0);
    display: flex; align-items: center; justify-content: center;
    font-size: 32px; font-weight: bold; color: #06090d;
  }
  h1 { color: #e6e9ef; margin-bottom: 4px; }
  .handle { color: #3ec9c9; font-family: monospace; margin-bottom: 18px; }
  .note { color:#7a8494; font-size:13px; text-align: left; background:#10141b; border:1px solid #1e2530; border-radius:8px; padding:14px; margin: 20px 0; }
  .insta-btn {
    display: inline-flex; align-items: center; gap: 8px;
    margin-top: 12px; padding: 12px 24px; border-radius: 8px;
    background: linear-gradient(45deg, #f09433, #e6683c, #dc2743, #cc2366, #bc1888);
    color: #fff; text-decoration: none; font-weight: 600; font-size: 15px;
  }
  .insta-btn:hover { opacity: 0.9; }
</style>
</head><body>
  <div class="profile-wrap">
    <div class="avatar">NR</div>
    <h1>Nandhu Rahul G</h1>
    <div class="handle">@nandhu_rahul_g</div>
    <p class="note">This page is protected by <b>ShieldChain</b> -- a small, self-owned
    endpoint used to generate and monitor <b>real</b> HTTP traffic for the ShieldChain
    DDoS-defense project. Every visit here is genuinely captured and classified, not
    simulated. See the main dashboard's "Real Traffic Monitor" panel for live detections.</p>
    {% for link in links %}
      <a class="insta-btn" href="{{ link.url }}" target="_blank" rel="noopener">
        {{ link.icon }} {{ link.label }}
      </a>
    {% endfor %}
  </div>
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


def register_shop_routes(app, monitor, detector, contract, chain, on_event=None, stats=None):
    """Wire the demo shop's routes into the main Flask app, sharing the
    same monitor/detector/contract/chain instances the dashboard uses.

    `stats`, if provided, is a shared mutable dict the caller can read
    from the dashboard's /api/state endpoint -- it tracks:
      - requests_received: every request that reached this Flask app for
        /shop, regardless of outcome (including ones immediately 429'd)
      - blocked_fastpath: requests rejected immediately because the
        source was already blacklisted, before any new classification
      - action_counts: running totals per mitigation action, across both
        real and simulated traffic (see app.py's process_one_flow)
    """
    if stats is None:
        stats = {}
    stats.setdefault("requests_received", 0)
    stats.setdefault("blocked_fastpath", 0)
    stats.setdefault("action_counts", {"allow": 0, "monitor": 0, "rate_limit": 0, "challenge": 0, "blacklist": 0})

    def get_source_id():
        # Respect X-Forwarded-For since Render sits behind a proxy;
        # fall back to remote_addr for local testing.
        fwd = request.headers.get("X-Forwarded-For", "")
        return fwd.split(",")[0].strip() if fwd else (request.remote_addr or "unknown")

    @app.before_request
    def _shop_gate():
        if not request.path.startswith("/shop"):
            return None  # not a protected route, let it through untouched

        stats["requests_received"] += 1
        source_id = get_source_id()
        if contract.is_blacklisted(source_id):
            stats["blocked_fastpath"] += 1
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

        # Deterministic rule-based backstop alongside the ML model -- see
        # request_monitor.rate_heuristic_label() docstring for why this
        # exists. If the ML model still says "benign" but the burst
        # pattern clearly matches a single-source flood, override it here
        # so real enforcement doesn't depend solely on the ML model
        # recognizing out-of-distribution traffic.
        heuristic_label = rate_heuristic_label(features, monitor.sample_count(source_id))
        if heuristic_label and result["predicted_label"] == "benign":
            result = dict(result)
            result["predicted_label"] = heuristic_label
            result["confidence"] = max(result["confidence"], 0.90)
            result["heuristic_override"] = True

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

        return render_template_string(SHOP_TEMPLATE, links=PROFILE_LINKS)

    return app
