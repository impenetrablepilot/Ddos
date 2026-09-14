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
    return pd.DataFrame({
        "packet_rate": rng.normal(120, 40, n).clip(1),
        "byte_rate": rng.normal(90_000, 30_000, n).clip(500),
        "avg_packet_size": rng.normal(650, 150, n).clip(64),
        "flow_duration": rng.exponential(8, n).clip(0.1),
        "syn_ratio": rng.beta(2, 20, n),
        "src_ip_entropy": rng.normal(3.2, 0.6, n).clip(0.5),
        "unique_src_ips": rng.integers(5, 60, n),
        "protocol_udp_frac": rng.beta(2, 8, n),
        "protocol_tcp_frac": rng.beta(8, 3, n),
        "protocol_http_frac": rng.beta(5, 5, n),
        "avg_inter_arrival": rng.exponential(0.05, n).clip(0.001),
        "label": "benign",
    })


def make_syn_flood(n, rng):
    return pd.DataFrame({
        "packet_rate": rng.normal(9000, 2500, n).clip(500),
        "byte_rate": rng.normal(500_000, 150_000, n).clip(10_000),
        "avg_packet_size": rng.normal(60, 10, n).clip(40),
        "flow_duration": rng.exponential(2, n).clip(0.05),
        "syn_ratio": rng.beta(20, 2, n),          # almost all SYN
        "src_ip_entropy": rng.normal(6.5, 0.8, n).clip(1),  # many spoofed IPs
        "unique_src_ips": rng.integers(500, 5000, n),
        "protocol_udp_frac": rng.beta(1, 20, n),
        "protocol_tcp_frac": rng.beta(20, 1, n),
        "protocol_http_frac": rng.beta(1, 30, n),
        "avg_inter_arrival": rng.exponential(0.0005, n).clip(0.00001),
        "label": "syn_flood",
    })


def make_udp_flood(n, rng):
    return pd.DataFrame({
        "packet_rate": rng.normal(12000, 3000, n).clip(500),
        "byte_rate": rng.normal(2_000_000, 500_000, n).clip(50_000),
        "avg_packet_size": rng.normal(1200, 200, n).clip(200),
        "flow_duration": rng.exponential(1.5, n).clip(0.05),
        "syn_ratio": rng.beta(1, 30, n),
        "src_ip_entropy": rng.normal(6.0, 0.9, n).clip(1),
        "unique_src_ips": rng.integers(300, 4000, n),
        "protocol_udp_frac": rng.beta(25, 1, n),
        "protocol_tcp_frac": rng.beta(1, 25, n),
        "protocol_http_frac": rng.beta(1, 30, n),
        "avg_inter_arrival": rng.exponential(0.0004, n).clip(0.00001),
        "label": "udp_flood",
    })


def make_http_flood(n, rng):
    return pd.DataFrame({
        "packet_rate": rng.normal(2500, 800, n).clip(200),
        "byte_rate": rng.normal(300_000, 90_000, n).clip(5_000),
        "avg_packet_size": rng.normal(400, 80, n).clip(100),
        "flow_duration": rng.exponential(15, n).clip(0.2),
        "syn_ratio": rng.beta(3, 15, n),
        "src_ip_entropy": rng.normal(2.0, 0.5, n).clip(0.2),  # fewer, persistent bots
        "unique_src_ips": rng.integers(50, 800, n),
        "protocol_udp_frac": rng.beta(1, 20, n),
        "protocol_tcp_frac": rng.beta(10, 5, n),
        "protocol_http_frac": rng.beta(25, 2, n),
        "avg_inter_arrival": rng.exponential(0.004, n).clip(0.0001),
        "label": "http_flood",
    })


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
