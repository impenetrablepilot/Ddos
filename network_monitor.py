"""
network_monitor.py
-------------------
GENUINE network/packet-layer DDoS detection and enforcement.

This is architecturally different from ml/request_monitor.py, and
deliberately cannot run as part of the Flask web app. It must run as a
standalone, root-privileged process on a machine you control (your own
PC or a VPS/dedicated server -- NOT Render or any shared PaaS, which
blocks raw packet capture for every tenant as a basic security measure).

What this gives you that the HTTP-layer monitor architecturally cannot:
  - REAL syn_ratio: computed from actual TCP SYN flags on the wire.
  - REAL protocol_udp_frac / protocol_tcp_frac: computed from actual
    IP protocol numbers, not inferred from an HTTP framework.
  - Detection of SYN floods and UDP floods -- the two attack types your
    web-layer /nandhu endpoint can never see, because by the time a
    request reaches Flask, the TCP handshake has already completed.

How it fits with the rest of the project:
  - Feature extraction here mirrors ml/request_monitor.py's schema
    exactly, so it can call the SAME trained model (ml/detector.py) with
    no retraining needed.
  - Confirmed detections are reported to your live dashboard via HTTPS
    POST to /api/network_event, so they show up in the same unified feed
    and blockchain ledger as your simulated and HTTP-layer traffic --
    tagged with layer="network" so you can tell them apart.
  - Enforcement is REAL and LOCAL: a confirmed attacker is blocked with
    an actual `iptables` DROP rule on this machine's firewall. This is
    the one piece that cannot be done remotely by the dashboard -- only
    a process with root on the actual machine being attacked can install
    a kernel firewall rule.

REQUIREMENTS (all must be true on the machine that runs this script):
  - Linux, with iptables installed (standard on most distros)
  - Root/sudo privileges (raw packet capture and firewall rules both
    require this)
  - Scapy installed: pip install scapy
  - Run on hardware/a VPS you own or are authorized to monitor -- never
    on infrastructure you don't control, and never configured to sniff
    or block traffic that isn't genuinely yours to defend.

Usage:
    sudo python3 network_monitor.py --iface eth0 \
        --dashboard-url https://your-app.onrender.com \
        --dashboard-key YOUR_SHARED_SECRET
"""
import argparse
import math
import subprocess
import sys
import time
import urllib.request
import json
from collections import defaultdict, deque

WINDOW_SECONDS = 5.0
GLOBAL_WINDOW_SECONDS = 10.0
CLASSIFY_EVERY_N_PACKETS = 20   # re-run classification after this many new packets per source


class NetworkFeatureTracker:
    """Mirrors ml/request_monitor.py's RequestMonitor, but fed from real
    packet captures instead of HTTP requests, so the same trained model
    can classify either source with no changes."""

    def __init__(self):
        self._by_source = defaultdict(deque)          # source_ip -> deque[(ts, size, proto, is_syn)]
        self._global_log = deque()                     # (ts, source_ip)
        self._first_seen = {}
        self._packet_count_since_classify = defaultdict(int)

    def record_packet(self, source_ip: str, size: int, proto: str, is_syn: bool):
        now = time.time()
        if source_ip not in self._first_seen:
            self._first_seen[source_ip] = now

        q = self._by_source[source_ip]
        q.append((now, size, proto, is_syn))
        self._global_log.append((now, source_ip))
        self._packet_count_since_classify[source_ip] += 1

        self._trim(q, now)
        self._trim_global(now)

    def should_classify(self, source_ip: str) -> bool:
        if self._packet_count_since_classify[source_ip] >= CLASSIFY_EVERY_N_PACKETS:
            self._packet_count_since_classify[source_ip] = 0
            return True
        return False

    def _trim(self, q, now):
        while q and now - q[0][0] > WINDOW_SECONDS:
            q.popleft()

    def _trim_global(self, now):
        while self._global_log and now - self._global_log[0][0] > GLOBAL_WINDOW_SECONDS:
            self._global_log.popleft()

    def extract_features(self, source_ip: str):
        now = time.time()
        entries = list(self._by_source[source_ip])
        n = len(entries)
        if n == 0:
            return None

        times = [e[0] for e in entries]
        sizes = [e[1] for e in entries]
        protos = [e[2] for e in entries]
        syn_flags = [e[3] for e in entries]

        window = max(times[-1] - times[0], 0.5) if n > 1 else WINDOW_SECONDS
        packet_rate = n / window
        byte_rate = sum(sizes) / window
        avg_packet_size = sum(sizes) / n
        flow_duration = now - self._first_seen.get(source_ip, now)

        if n > 1:
            gaps = [times[i] - times[i - 1] for i in range(1, n)]
            avg_inter_arrival = sum(gaps) / len(gaps)
        else:
            avg_inter_arrival = WINDOW_SECONDS

        syn_ratio = sum(syn_flags) / n                                  # REAL, from actual TCP flags
        protocol_tcp_frac = sum(1 for p in protos if p == "TCP") / n    # REAL
        protocol_udp_frac = sum(1 for p in protos if p == "UDP") / n    # REAL
        protocol_http_frac = sum(1 for p in protos if p == "HTTP") / n  # heuristic: TCP port 80/443

        recent_sources = [s for (_, s) in self._global_log]
        unique_src_ips = len(set(recent_sources)) or 1
        src_ip_entropy = self._entropy(recent_sources)

        return {
            "packet_rate": round(packet_rate, 4),
            "byte_rate": round(byte_rate, 4),
            "avg_packet_size": round(avg_packet_size, 4),
            "flow_duration": round(flow_duration, 4),
            "syn_ratio": round(syn_ratio, 4),
            "src_ip_entropy": round(src_ip_entropy, 4),
            "unique_src_ips": unique_src_ips,
            "protocol_udp_frac": round(protocol_udp_frac, 4),
            "protocol_tcp_frac": round(protocol_tcp_frac, 4),
            "protocol_http_frac": round(protocol_http_frac, 4),
            "avg_inter_arrival": round(avg_inter_arrival, 4),
        }

    @staticmethod
    def _entropy(items):
        if not items:
            return 0.0
        counts = defaultdict(int)
        for i in items:
            counts[i] += 1
        total = len(items)
        ent = 0.0
        for c in counts.values():
            p = c / total
            ent -= p * math.log2(p)
        return ent


def classify_packet(pkt):
    """Extract (source_ip, size, proto, is_syn) from one captured packet.
    Kept as a standalone function so it can be unit-tested with a fake
    packet object, without needing a real network interface or root."""
    from scapy.layers.inet import IP, TCP, UDP  # imported lazily so this
    # module can still be imported (and its feature-extraction logic
    # tested) on a machine without Scapy installed.

    if IP not in pkt:
        return None
    src_ip = pkt[IP].src
    size = len(pkt)

    if TCP in pkt:
        proto = "HTTP" if pkt[TCP].dport in (80, 443) or pkt[TCP].sport in (80, 443) else "TCP"
        is_syn = bool(pkt[TCP].flags & 0x02) and not bool(pkt[TCP].flags & 0x10)  # SYN set, ACK not set
        return src_ip, size, proto, is_syn
    elif UDP in pkt:
        return src_ip, size, "UDP", False
    else:
        return src_ip, size, "OTHER", False


class IptablesEnforcer:
    """Real, local firewall enforcement. Requires root."""

    def __init__(self, dry_run=False):
        self.dry_run = dry_run
        self._blocked = set()

    def block(self, source_ip: str) -> bool:
        if source_ip in self._blocked:
            return True
        cmd = ["iptables", "-A", "INPUT", "-s", source_ip, "-j", "DROP"]
        if self.dry_run:
            print(f"[dry-run] would run: {' '.join(cmd)}")
            self._blocked.add(source_ip)
            return True
        try:
            subprocess.run(cmd, check=True, capture_output=True)
            self._blocked.add(source_ip)
            return True
        except subprocess.CalledProcessError as e:
            print(f"iptables block failed for {source_ip}: {e.stderr.decode()}", file=sys.stderr)
            return False
        except FileNotFoundError:
            print("iptables not found -- this script requires Linux with iptables installed.", file=sys.stderr)
            return False

    def is_blocked(self, source_ip: str) -> bool:
        return source_ip in self._blocked


def report_to_dashboard(dashboard_url, dashboard_key, event):
    """POST a confirmed network-layer detection to the live dashboard so
    it appears in the same unified feed/ledger as simulated and
    HTTP-layer traffic (see app.py's /api/network_event endpoint)."""
    try:
        req = urllib.request.Request(
            f"{dashboard_url.rstrip('/')}/api/network_event",
            data=json.dumps(event).encode(),
            headers={"Content-Type": "application/json", "X-Shared-Key": dashboard_key},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=5)
        return True
    except Exception as e:
        print(f"Could not report to dashboard (continuing locally regardless): {e}", file=sys.stderr)
        return False


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--iface", required=True, help="Network interface to monitor, e.g. eth0")
    ap.add_argument("--dashboard-url", required=True, help="Your deployed ShieldChain dashboard URL")
    ap.add_argument("--dashboard-key", default="", help="Shared secret matching the dashboard's NETWORK_MONITOR_KEY")
    ap.add_argument("--dry-run", action="store_true", help="Log what WOULD be blocked, without touching iptables")
    args = ap.parse_args()

    try:
        from scapy.all import sniff
    except ImportError:
        print("Scapy is not installed. Run: pip install scapy", file=sys.stderr)
        sys.exit(1)

    sys.path.append("ml")
    from detector import Detector  # the SAME trained model used everywhere else in the project

    tracker = NetworkFeatureTracker()
    enforcer = IptablesEnforcer(dry_run=args.dry_run)
    detector = Detector()
    strikes = defaultdict(int)

    print(f"Monitoring {args.iface} -- Ctrl+C to stop. Dry run: {args.dry_run}")

    def handle_packet(pkt):
        parsed = classify_packet(pkt)
        if parsed is None:
            return
        source_ip, size, proto, is_syn = parsed
        tracker.record_packet(source_ip, size, proto, is_syn)

        if enforcer.is_blocked(source_ip):
            return  # already handled; don't re-classify a known attacker every packet

        if tracker.should_classify(source_ip):
            features = tracker.extract_features(source_ip)
            if features is None:
                return
            result = detector.classify(features)
            label, confidence = result["predicted_label"], result["confidence"]

            if label != "benign" and confidence >= 0.60:
                strikes[source_ip] += 1
                action = "blacklist" if strikes[source_ip] >= 2 else "rate_limit"
                if action == "blacklist":
                    enforcer.block(source_ip)
                print(f"[{action}] {source_ip} -> {label} ({confidence:.2f})")
                report_to_dashboard(args.dashboard_url, args.dashboard_key, {
                    "source_id": source_ip,
                    "predicted_label": label,
                    "confidence": confidence,
                    "mitigation_action": action,
                    "layer": "network",
                })

    sniff(iface=args.iface, prn=handle_packet, filter="ip", store=False)


if __name__ == "__main__":
    main()
