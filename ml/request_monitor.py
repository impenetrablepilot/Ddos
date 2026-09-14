"""
request_monitor.py
-------------------
Monitors REAL incoming HTTP requests to the protected demo site and
extracts a feature vector in the same schema the ML model was trained on
(see data/generate_traffic.py), computed from genuine request activity
rather than simulated.

IMPORTANT ARCHITECTURAL LIMITATION (read this before assuming this
detects all DDoS types): a Flask application only ever sees HTTP-layer
traffic. By the time a request reaches this code, the TCP handshake has
already completed. This means:

  - syn_ratio is structurally unobservable here and is always 0.0 --
    detecting a SYN flood requires packet-level network capture (e.g.
    Scapy/tcpdump) sitting in front of the TCP stack, which is out of
    scope for a Flask application and is documented as future work in
    the project report.
  - protocol_udp_frac is always 0.0 for the same reason -- a Flask app
    never observes non-HTTP protocol traffic.
  - protocol_tcp_frac / protocol_http_frac are fixed at 1.0 since every
    request that reaches this code is, by definition, HTTP-over-TCP.

What this monitor CAN genuinely detect: HTTP-flood-style application
layer abuse -- a high rate of real requests from one source, unusually
regular timing (bot-like), or a large share of total site traffic
concentrated on very few source IPs. This is a real, meaningful subset
of DDoS defense (Slowloris/HTTP-flood-class attacks specifically operate
at this layer), just not the full space of attacks the synthetic
training data covers.
"""
import time
import math
from collections import defaultdict, deque
from typing import Dict, Any, Optional

WINDOW_SECONDS = 5.0        # sliding window used to compute per-source rate features
GLOBAL_WINDOW_SECONDS = 10.0  # window used to compute site-wide source-IP entropy


class RequestMonitor:
    def __init__(self):
        # per-source request timestamps (for rate / inter-arrival / flow duration)
        self._by_source: Dict[str, deque] = defaultdict(deque)
        # per-source total bytes seen in the current window (request + response size)
        self._by_source_bytes: Dict[str, deque] = defaultdict(deque)
        # global recent (timestamp, source) log, for site-wide unique-IP / entropy features
        self._global_log: deque = deque()
        # first-seen time per source, for flow_duration
        self._first_seen: Dict[str, float] = {}

    def record_and_extract(self, source_id: str, request_bytes: int) -> Dict[str, Any]:
        """Record one real incoming request and return a feature vector for it,
        computed only from genuine traffic observed so far."""
        now = time.time()

        if source_id not in self._first_seen:
            self._first_seen[source_id] = now

        src_times = self._by_source[source_id]
        src_bytes = self._by_source_bytes[source_id]
        src_times.append(now)
        src_bytes.append(request_bytes)
        self._global_log.append((now, source_id))

        self._trim(src_times, src_bytes, now)
        self._trim_global(now)

        return self._compute_features(source_id, now)

    def _trim(self, times: deque, byte_q: deque, now: float):
        while times and now - times[0] > WINDOW_SECONDS:
            times.popleft()
            if byte_q:
                byte_q.popleft()

    def _trim_global(self, now: float):
        while self._global_log and now - self._global_log[0][0] > GLOBAL_WINDOW_SECONDS:
            self._global_log.popleft()

    def _compute_features(self, source_id: str, now: float) -> Dict[str, Any]:
        times = list(self._by_source[source_id])
        byte_sizes = list(self._by_source_bytes[source_id])
        n = len(times)

        window = max(now - times[0], 0.5) if n > 1 else WINDOW_SECONDS
        packet_rate = n / window if window > 0 else float(n)  # requests/sec, proxy for packet_rate
        byte_rate = sum(byte_sizes) / window if window > 0 else 0.0
        avg_packet_size = (sum(byte_sizes) / n) if n else 0.0
        flow_duration = now - self._first_seen.get(source_id, now)

        if n > 1:
            gaps = [times[i] - times[i - 1] for i in range(1, n)]
            avg_inter_arrival = sum(gaps) / len(gaps)
        else:
            avg_inter_arrival = WINDOW_SECONDS

        # Site-wide features over the global recent window
        recent_sources = [s for (_, s) in self._global_log]
        unique_src_ips = len(set(recent_sources)) or 1
        src_ip_entropy = self._shannon_entropy(recent_sources)

        return {
            "packet_rate": round(packet_rate, 4),
            "byte_rate": round(byte_rate, 4),
            "avg_packet_size": round(avg_packet_size, 4),
            "flow_duration": round(flow_duration, 4),
            "syn_ratio": 0.0,                # unobservable at HTTP layer -- see module docstring
            "src_ip_entropy": round(src_ip_entropy, 4),
            "unique_src_ips": unique_src_ips,
            "protocol_udp_frac": 0.0,        # unobservable at HTTP layer -- see module docstring
            "protocol_tcp_frac": 1.0,        # every HTTP request rides on TCP
            "protocol_http_frac": 1.0,       # this monitor only ever sees HTTP traffic
            "avg_inter_arrival": round(avg_inter_arrival, 4),
        }

    @staticmethod
    def _shannon_entropy(items) -> float:
        if not items:
            return 0.0
        counts = defaultdict(int)
        for i in items:
            counts[i] += 1
        total = len(items)
        entropy = 0.0
        for c in counts.values():
            p = c / total
            entropy -= p * math.log2(p)
        return entropy
