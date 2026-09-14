"""
smart_contract.py
------------------
Simulates the role a Solidity smart contract would play on a real
Ethereum deployment: it receives a detection event from the ML module,
applies deterministic mitigation rules, and returns the action to record
on the blockchain ledger. A reference Solidity contract with the same
fields/logic is provided in smart_contract.sol for anyone who wants to
deploy this on an actual Ethereum test network (Ganache/Hardhat).

Rules (mirrors a typical automated-response policy):
  - benign                -> no action
  - confidence < 0.60     -> monitor only (avoid false-positive blocking)
  - syn_flood / udp_flood -> rate_limit source, then blacklist if it recurs
  - http_flood            -> challenge (CAPTCHA-style) then blacklist if it recurs
"""
from collections import defaultdict
from typing import Any, Dict

CONFIDENCE_THRESHOLD = 0.60
REPEAT_OFFENSE_THRESHOLD = 2  # strikes before a hard blacklist


class MitigationContract:
    """Stateful rule engine — 'state' here plays the role that contract
    storage would play on-chain (tracked per source node/IP)."""

    def __init__(self):
        self._strikes = defaultdict(int)
        self._blacklisted = set()

    def is_blacklisted(self, source_id: str) -> bool:
        """Real enforcement check -- called before serving a request to
        the protected demo site (see protected_site.py)."""
        return source_id in self._blacklisted

    def reset(self):
        """Clear all strikes and blacklist entries, in place -- so any
        other module holding a reference to this same MitigationContract
        instance (e.g. protected_site.py) sees the reset too."""
        self._strikes = defaultdict(int)
        self._blacklisted = set()

    def evaluate(self, detection_event: Dict[str, Any]) -> Dict[str, Any]:
        label = detection_event["predicted_label"]
        confidence = detection_event["confidence"]
        source_id = detection_event.get("source_id", "unknown")

        if label == "benign":
            return self._action("allow", "Traffic classified as benign — no action taken.", source_id)

        if confidence < CONFIDENCE_THRESHOLD:
            return self._action("monitor", f"Low-confidence anomaly ({confidence:.2f}) — flagged for monitoring only.", source_id)

        self._strikes[source_id] += 1
        strikes = self._strikes[source_id]

        if label in ("syn_flood", "udp_flood"):
            if strikes >= REPEAT_OFFENSE_THRESHOLD:
                self._blacklisted.add(source_id)
                return self._action("blacklist", f"Repeated {label} detected ({strikes}x) — source blacklisted.", source_id)
            return self._action("rate_limit", f"{label} detected — rate-limiting source.", source_id)

        if label == "http_flood":
            if strikes >= REPEAT_OFFENSE_THRESHOLD:
                self._blacklisted.add(source_id)
                return self._action("blacklist", f"Repeated http_flood detected ({strikes}x) — source blacklisted.", source_id)
            return self._action("challenge", "http_flood pattern detected — issuing challenge (CAPTCHA-equivalent).", source_id)

        return self._action("monitor", "Unrecognized attack label — flagged for manual review.", source_id)

    @staticmethod
    def _action(action: str, reason: str, source_id: str) -> Dict[str, Any]:
        return {"action": action, "reason": reason, "source_id": source_id}
