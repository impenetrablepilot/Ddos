"""
generate_traffic.py
--------------------
Generates a synthetic, labeled network-traffic dataset that mimics the
statistical signature of legitimate traffic and three common DDoS attack
types (SYN flood, UDP flood, HTTP flood).

Why synthetic data: this project runs fully offline / without any external
dataset download. The feature set (packet rate, source-IP entropy,
SYN ratio, protocol mix, avg packet size, flow duration) mirrors the
features typically used with public benchmark sets such as CICDDoS2019,
so the same pipeline can be pointed at a real dataset later by replacing
this script's output with real CSV data of the same schema.

Run:
    python generate_traffic.py --rows 20000 --out dataset.csv
"""
import argparse
import numpy as np
import pandas as pd


FEATURES = [
    "packet_rate",       # packets/sec seen in the flow window
    "byte_rate",         # bytes/sec
    "avg_packet_size",   # bytes
    "flow_duration",     # seconds
    "syn_ratio",         # fraction of packets that are SYN
    "src_ip_entropy",    # Shannon entropy of source IPs in the window (0 = single IP, high = many)
    "unique_src_ips",    # count of distinct source IPs in the window
    "protocol_udp_frac", # fraction of packets that are UDP
    "protocol_tcp_frac", # fraction of packets that are TCP
    "protocol_http_frac",# fraction of packets that are HTTP requests
    "avg_inter_arrival", # avg seconds between packets
]


def make_benign(n, rng):
    """Two benign regimes are blended here:

    1. multi_user   -- typical production traffic with several concurrent
       visitors (the original, only regime this function generated).
    2. lone_visitor -- a single real visitor browsing normally: low,
       human-paced request rate, but (critically) unique_src_ips=1 and
       src_ip_entropy=0, exactly like a single-source flood's source
       diversity. Without this regime the model had never seen a benign
       example with low source diversity, so it treated ANY single-source
       traffic as an attack regardless of rate -- including one legitimate
       page load. Including this regime teaches the model that packet_rate
       (human-paced vs. bot-paced) is what actually separates a lone
       visitor from a lone attacker, not source diversity alone.
    """
    n_multi = int(n * 0.75)
    n_lone = n - n_multi

    multi_user = pd.DataFrame({
        "packet_rate": rng.normal(120, 40, n_multi).clip(1),
        "byte_rate": rng.normal(90_000, 30_000, n_multi).clip(500),
        "avg_packet_size": rng.normal(650, 150, n_multi).clip(64),
        "flow_duration": rng.exponential(8, n_multi).clip(0.1),
        "syn_ratio": rng.beta(2, 20, n_multi),
        "src_ip_entropy": rng.normal(3.2, 0.6, n_multi).clip(0.5),
        "unique_src_ips": rng.integers(5, 60, n_multi),
        "protocol_udp_frac": rng.beta(2, 8, n_multi),
        "protocol_tcp_frac": rng.beta(8, 3, n_multi),
        "protocol_http_frac": rng.beta(5, 5, n_multi),
        "avg_inter_arrival": rng.exponential(0.05, n_multi).clip(0.001),
    })

    lone_visitor = pd.DataFrame({
        "packet_rate": rng.uniform(0.05, 3.0, n_lone),          # human page-load pace, well under the http_flood heuristic/model range
        "byte_rate": rng.uniform(200, 4_000, n_lone),
        "avg_packet_size": rng.normal(500, 120, n_lone).clip(64),
        "flow_duration": rng.exponential(10, n_lone).clip(0.1),
        "syn_ratio": np.zeros(n_lone),
        "src_ip_entropy": np.zeros(n_lone),                     # only one source active -- same as a real lone visitor
        "unique_src_ips": np.ones(n_lone, dtype=int),
        "protocol_udp_frac": np.zeros(n_lone),
        "protocol_tcp_frac": np.ones(n_lone),
        "protocol_http_frac": np.ones(n_lone),
        "avg_inter_arrival": rng.uniform(0.5, 8.0, n_lone),     # seconds between clicks/page loads -- human-paced, not bot-paced
    })

    df = pd.concat([multi_user, lone_visitor], ignore_index=True)
    df["label"] = "benign"
    return df


def make_syn_flood(n, rng):
    """Two syn_flood regimes are blended here, mirroring make_http_flood's
    distributed/single_source split (see that function's docstring for
    the full rationale). A real SYN flood is conventionally launched from
    many spoofed source addresses (the 'distributed' regime below), but a
    single, non-spoofed attacking machine -- e.g. one compromised, powerful
    server, or the kind of single-machine test this project's own
    network_monitor.py performs -- is also a genuine, real-world case, and
    was found to score only marginally (~0.58 confidence, just under the
    0.60 mitigation threshold) against a model trained only on the
    distributed regime, since unique_src_ips=1 / src_ip_entropy=0 had never
    been paired with a genuine attack-rate example for this class.
    """
    n_distributed = n // 2
    n_single_source = n - n_distributed

    distributed = pd.DataFrame({
        "packet_rate": rng.normal(9000, 2500, n_distributed).clip(500),
        "byte_rate": rng.normal(500_000, 150_000, n_distributed).clip(10_000),
        "avg_packet_size": rng.normal(60, 10, n_distributed).clip(40),
        "flow_duration": rng.exponential(2, n_distributed).clip(0.05),
        "syn_ratio": rng.beta(20, 2, n_distributed),          # almost all SYN
        "src_ip_entropy": rng.normal(6.5, 0.8, n_distributed).clip(1),  # many spoofed IPs
        "unique_src_ips": rng.integers(500, 5000, n_distributed),
        "protocol_udp_frac": rng.beta(1, 20, n_distributed),
        "protocol_tcp_frac": rng.beta(20, 1, n_distributed),
        "protocol_http_frac": rng.beta(1, 30, n_distributed),
        "avg_inter_arrival": rng.exponential(0.0005, n_distributed).clip(0.00001),
    })

    single_source = pd.DataFrame({
        "packet_rate": rng.normal(9000, 2500, n_single_source).clip(500),  # same real attack rate
        "byte_rate": rng.normal(500_000, 150_000, n_single_source).clip(10_000),
        "avg_packet_size": rng.normal(60, 10, n_single_source).clip(40),
        "flow_duration": rng.exponential(2, n_single_source).clip(0.05),
        "syn_ratio": rng.beta(20, 2, n_single_source),
        "src_ip_entropy": np.zeros(n_single_source),           # one real, non-spoofed source
        "unique_src_ips": rng.integers(1, 3, n_single_source),
        "protocol_udp_frac": rng.beta(1, 20, n_single_source),
        "protocol_tcp_frac": rng.beta(20, 1, n_single_source),
        "protocol_http_frac": rng.beta(1, 30, n_single_source),
        "avg_inter_arrival": rng.exponential(0.0005, n_single_source).clip(0.00001),
    })

    df = pd.concat([distributed, single_source], ignore_index=True)
    df["label"] = "syn_flood"
    return df


def make_udp_flood(n, rng):
    """Same distributed/single_source blend as make_syn_flood, for the
    same reason: a single real machine capable of a genuine UDP flood
    (e.g. via a misconfigured amplification relay it controls) is a real
    case the original distributed-only training data didn't cover."""
    n_distributed = n // 2
    n_single_source = n - n_distributed

    distributed = pd.DataFrame({
        "packet_rate": rng.normal(12000, 3000, n_distributed).clip(500),
        "byte_rate": rng.normal(2_000_000, 500_000, n_distributed).clip(50_000),
        "avg_packet_size": rng.normal(1200, 200, n_distributed).clip(200),
        "flow_duration": rng.exponential(1.5, n_distributed).clip(0.05),
        "syn_ratio": rng.beta(1, 30, n_distributed),
        "src_ip_entropy": rng.normal(6.0, 0.9, n_distributed).clip(1),
        "unique_src_ips": rng.integers(300, 4000, n_distributed),
        "protocol_udp_frac": rng.beta(25, 1, n_distributed),
        "protocol_tcp_frac": rng.beta(1, 25, n_distributed),
        "protocol_http_frac": rng.beta(1, 30, n_distributed),
        "avg_inter_arrival": rng.exponential(0.0004, n_distributed).clip(0.00001),
    })

    single_source = pd.DataFrame({
        "packet_rate": rng.normal(12000, 3000, n_single_source).clip(500),
        "byte_rate": rng.normal(2_000_000, 500_000, n_single_source).clip(50_000),
        "avg_packet_size": rng.normal(1200, 200, n_single_source).clip(200),
        "flow_duration": rng.exponential(1.5, n_single_source).clip(0.05),
        "syn_ratio": rng.beta(1, 30, n_single_source),
        "src_ip_entropy": np.zeros(n_single_source),
        "unique_src_ips": rng.integers(1, 3, n_single_source),
        "protocol_udp_frac": rng.beta(25, 1, n_single_source),
        "protocol_tcp_frac": rng.beta(1, 25, n_single_source),
        "protocol_http_frac": rng.beta(1, 30, n_single_source),
        "avg_inter_arrival": rng.exponential(0.0004, n_single_source).clip(0.00001),
    })

    df = pd.concat([distributed, single_source], ignore_index=True)
    df["label"] = "udp_flood"
    return df


def make_http_flood(n, rng):
    """Two http_flood regimes are blended here:

    1. distributed  -- a large botnet-style flood (many source IPs, very
       high packet rate). This was the original (and only) regime this
       function generated.
    2. single_source -- a single-client, HTTP-layer burst: the pattern a
       Flask app actually observes when one real machine hammers it
       (see ml/request_monitor.py). Rates here are far lower than a
       botnet flood but still well above normal single-user browsing,
       and syn_ratio/protocol_udp_frac are pinned to 0 since a Flask app
       can never observe those at this layer. Without this regime the
       trained classifier only recognizes large distributed floods and
       will call a genuine single-source burst "benign" (out-of-
       distribution input), regardless of how aggressive it is.
    """
    n_distributed = n // 2
    n_single_source = n - n_distributed

    distributed = pd.DataFrame({
        "packet_rate": rng.normal(2500, 800, n_distributed).clip(200),
        "byte_rate": rng.normal(300_000, 90_000, n_distributed).clip(5_000),
        "avg_packet_size": rng.normal(400, 80, n_distributed).clip(100),
        "flow_duration": rng.exponential(15, n_distributed).clip(0.2),
        "syn_ratio": rng.beta(3, 15, n_distributed),
        "src_ip_entropy": rng.normal(2.0, 0.5, n_distributed).clip(0.2),
        "unique_src_ips": rng.integers(50, 800, n_distributed),
        "protocol_udp_frac": rng.beta(1, 20, n_distributed),
        "protocol_tcp_frac": rng.beta(10, 5, n_distributed),
        "protocol_http_frac": rng.beta(25, 2, n_distributed),
        "avg_inter_arrival": rng.exponential(0.004, n_distributed).clip(0.0001),
    })

    single_source = pd.DataFrame({
        "packet_rate": rng.uniform(5, 60, n_single_source),
        "byte_rate": rng.uniform(1_000, 20_000, n_single_source),
        "avg_packet_size": rng.normal(250, 60, n_single_source).clip(80),
        "flow_duration": rng.exponential(6, n_single_source).clip(0.2),
        "syn_ratio": np.zeros(n_single_source),
        "src_ip_entropy": rng.uniform(0.0, 0.3, n_single_source),
        "unique_src_ips": rng.integers(1, 3, n_single_source),
        "protocol_udp_frac": np.zeros(n_single_source),
        "protocol_tcp_frac": np.ones(n_single_source),
        "protocol_http_frac": np.ones(n_single_source),
        "avg_inter_arrival": rng.uniform(0.01, 0.2, n_single_source),
    })

    df = pd.concat([distributed, single_source], ignore_index=True)
    df["label"] = "http_flood"
    return df


def build_dataset(n_rows, attack_fraction, seed):
    rng = np.random.default_rng(seed)
    n_attack = int(n_rows * attack_fraction)
    n_benign = n_rows - n_attack
    n_each_attack = n_attack // 3

    parts = [
        make_benign(n_benign, rng),
        make_syn_flood(n_each_attack, rng),
        make_udp_flood(n_each_attack, rng),
        make_http_flood(n_attack - 2 * n_each_attack, rng),
    ]
    df = pd.concat(parts, ignore_index=True)
    df = df.sample(frac=1, random_state=seed).reset_index(drop=True)

    # binary label used for the primary classifier
    df["is_attack"] = (df["label"] != "benign").astype(int)
    return df


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--rows", type=int, default=20000)
    ap.add_argument("--attack-fraction", type=float, default=0.35)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", type=str, default="dataset.csv")
    args = ap.parse_args()

    df = build_dataset(args.rows, args.attack_fraction, args.seed)
    df.to_csv(args.out, index=False)
    print(f"Wrote {len(df)} rows to {args.out}")
    print(df["label"].value_counts())
