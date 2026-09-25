# Network-Layer Monitoring Extension (network_monitor.py)

This extends ShieldChain beyond the web-application layer to genuine
SYN-flood and UDP-flood detection at the packet level — the two attack
types `/nandhu` (the Flask-based monitor) architecturally cannot see,
because by the time a request reaches Flask code, the TCP handshake has
already completed.

## Why this can't run on Render

Real packet capture requires raw-socket access to a network interface,
which needs root/administrator privileges. Render (and every shared
free-tier PaaS) deliberately blocks this for all tenants as a basic
security measure — there is no configuration that unlocks it. This
component **must** run as a separate, standalone process on a machine
you actually control: your own PC, or a VPS/dedicated server (e.g. a
DigitalOcean droplet, AWS EC2 instance) where you have root/sudo access.

## What it does

1. Sniffs real packets on a chosen network interface using Scapy.
2. Extracts a feature vector matching the exact schema your existing
   trained model expects — but with **genuinely real** `syn_ratio`,
   `protocol_udp_frac`, and `protocol_tcp_frac`, computed from actual
   TCP flags and IP protocol numbers (these are always 0.0/fixed in the
   HTTP-layer monitor, since Flask can't observe them).
3. Classifies each source using the *same* trained model already in
   `models/` — no separate model, no retraining required to use this.
4. On a confirmed attack, blocks the source for real using `iptables`
   (Linux's kernel firewall) — genuine enforcement, not a log entry.
5. Reports the confirmed detection to your live dashboard via an HTTPS
   POST to `/api/network_event`, so it appears in the same unified feed
   and blockchain ledger as your simulated and HTTP-layer traffic,
   tagged `"layer": "network"` to distinguish it.

## Setup

On a Linux machine/VPS you own, with root access:

```bash
pip install scapy
sudo python3 network_monitor.py \
    --iface eth0 \
    --dashboard-url https://your-app.onrender.com \
    --dashboard-key YOUR_SHARED_SECRET \
    --dry-run
```

- `--iface`: your network interface name (`ip a` on Linux will list them;
  commonly `eth0`, `ens5`, or similar on a cloud VPS).
- `--dashboard-key`: must match the `NETWORK_MONITOR_KEY` environment
  variable set on your Render deployment (Render → Environment tab).
  Without matching keys, the dashboard will reject the reports with a
  403, exactly as tested.
- `--dry-run`: **strongly recommended for your first run.** Logs what
  *would* be blocked without actually touching `iptables`, so you can
  confirm detection behaves correctly before enabling real firewall
  changes. Remove this flag only once you've verified the dry-run output
  looks right.

## Safety and scope

- Only ever run this against a network interface and traffic you are
  authorized to monitor. Running packet capture on a network you don't
  own or don't have permission to monitor is both a policy violation on
  most networks and, depending on jurisdiction, potentially illegal.
- The `iptables` rules this adds are appended to your `INPUT` chain and
  persist until removed or the machine reboots (unless you've configured
  `iptables-persistent` or similar). To review/clear them manually:
  ```bash
  sudo iptables -L INPUT -n --line-numbers   # view current rules
  sudo iptables -D INPUT <line-number>       # remove a specific rule
  ```
- This script has been verified in this project via: (a) unit-testing
  the packet-parsing logic (`classify_packet`) against constructed mock
  packets confirming SYN vs. ACK vs. SYN-ACK vs. UDP are all correctly
  distinguished, and (b) feeding realistic, properly-timed synthetic
  packet sequences through the real feature-extraction and real trained
  model, confirming single-source SYN and UDP floods are now correctly
  detected at high confidence after the training-data fix described
  below. It has **not** been tested against a live network interface or
  real iptables execution, since this project's development sandbox has
  no network access or root privileges — you should validate both with
  `--dry-run` before trusting it in any real deployment.

## The single-source detection gap (and why it was fixed the same way as before)

Initial testing (using realistic, properly-timed synthetic packet
sequences) found that a **single-source** SYN or UDP flood — one real
attacking machine, not a distributed botnet — scored only borderline
confidence (0.58 and 0.69 respectively, close to or under the 0.60
mitigation threshold), because the original training data only modeled
distributed attacks from hundreds–thousands of spoofed source IPs.

This is the exact same class of gap already found and fixed for
`http_flood` (see the main report's discovery-and-correction chapter):
the model had never seen an attack-rate example paired with low source
diversity. The fix follows the identical pattern — `data/generate_traffic.py`
now blends a `distributed` regime (many spoofed sources, as before) with
a `single_source` regime (one real source, same attack-level rate) for
**both** `syn_flood` and `udp_flood`, and the model was retrained on the
corrected data.

After retraining, single-source SYN flood confidence rose from 0.58 to
0.98, and single-source UDP flood rose from 0.69 to 1.0, while benign
single-source control cases (a lone real visitor, a single legitimate
connection open) were re-verified to still correctly classify as benign
— confirming the fix addressed the gap without introducing a new false
positive, the same verification discipline applied to the earlier
HTTP-layer fix.
