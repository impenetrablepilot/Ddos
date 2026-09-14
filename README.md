# ShieldChain — ML + Blockchain DDoS Detection & Mitigation

A working prototype accompanying the project report "Machine Learning –
Blockchain Based DDoS Detection and Mitigation System." It demonstrates the
full pipeline described in the report: traffic capture → ML classification
→ blockchain-anchored, smart-contract-triggered mitigation → live dashboard.

## What's inside

```
ddos_project/
├── data/
│   └── generate_traffic.py   # builds the labeled synthetic traffic dataset
├── ml/
│   ├── train_model.py        # trains RandomForest + IsolationForest
│   ├── detector.py           # loads models, classifies a traffic flow
│   └── live_traffic.py       # simulates a live stream of flow samples
├── blockchain/
│   ├── blockchain.py         # PoW hash-chain ledger (Python)
│   ├── smart_contract.py     # mitigation rule engine (Python, on-chain logic)
│   └── smart_contract.sol    # reference Solidity contract, same logic,
│                              # for deploying on a real Ethereum testnet later
├── models/                   # trained model artifacts (.joblib) + metrics.json
├── templates/index.html      # dashboard UI
├── app.py                    # Flask app tying it all together
└── requirements.txt
```

## Why synthetic traffic instead of a downloaded dataset

The dataset is generated programmatically (`data/generate_traffic.py`) rather
than downloaded from CICDDoS2019/NSL-KDD, so the whole project runs offline
with no external downloads. It uses the same feature schema those public
datasets use (packet rate, byte rate, SYN ratio, source-IP entropy, protocol
mix, inter-arrival time, etc.), so `train_model.py` can be pointed at a real
CSV of the same column names later — just replace `dataset.csv`.

Because the synthetic attack/benign distributions are cleanly separated,
the classifier reaches ~100% test accuracy. **Report this honestly** in your
results section — note that real-world traffic overlaps far more, and if
you want more realistic numbers for the write-up, download CICDDoS2019 on a
machine with internet access and retrain on it with the same pipeline.

## Why a Python blockchain instead of Ethereum/Ganache

`blockchain/blockchain.py` implements a genuine proof-of-work hash chain
(SHA-256, adjustable difficulty, full chain validation) so it demonstrates
the actual properties — immutability, tamper-evidence — that the report
attributes to blockchain, without requiring Node/Ganache/Truffle installed.
`blockchain/smart_contract.sol` is a reference Solidity contract with the
identical mitigation logic, included so you can deploy it on a local
Ethereum testnet (Ganache + Remix/Hardhat) if your coursework requires an
actual smart contract deployment/demo.

## Setup

```bash
pip install -r requirements.txt

# 1. Generate the dataset
python data/generate_traffic.py --rows 20000 --out data/dataset.csv

# 2. Train the models
python ml/train_model.py --data data/dataset.csv

# 3. Run the dashboard
python app.py
```

Then open **http://localhost:5000**.

## Using the dashboard

- **Send legitimate request** — simulates one normal user flow.
- **Launch SYN / UDP / HTTP flood** — simulates a burst of attack traffic
  from a synthetic botnet source; watch it get classified, mitigated, and
  logged to the blockchain in real time.
- **Simulate mixed traffic ×20** — a realistic mix of mostly-benign traffic
  with occasional attacks, like a live network feed.
- The **ledger panel** shows each mitigation event as a mined block (proof-
  of-work hash, linked to the previous block). Chain validity is checked
  live on every refresh.
- Repeated attacks from the same synthetic source escalate from
  `rate_limit`/`challenge` to `blacklist`, matching the mitigation policy
  described in Chapter 4 of the report.

## Real traffic monitoring (the /shop demo site)

Beyond the simulated-traffic buttons, the dashboard now also monitors
**genuine** HTTP traffic against a small, self-owned demo site at `/shop`.
This is a real addition, not another simulation:

- Every request to `/shop` is captured by `ml/request_monitor.py`, which
  computes real features (request rate, request size, source-IP entropy,
  inter-arrival time) from actual traffic — nothing here is generated or
  faked.
- Those real features are classified by the exact same trained model used
  for the simulated dashboard traffic.
- A genuinely blacklisted source gets a real HTTP 429 response and never
  sees the shop page — this is real enforcement, not just a log entry.
- Real detections appear in the same dashboard feed and blockchain ledger
  as simulated ones, marked with a 🌐 icon so you can tell them apart.

### Important architectural limitation (be upfront about this in your viva)

A Flask application only ever sees **HTTP-layer** traffic — by the time a
request reaches Python code, the TCP handshake has already completed.
This means:

- **SYN floods and UDP floods cannot be detected here** — `syn_ratio` and
  `protocol_udp_frac` are structurally fixed at 0.0 in `request_monitor.py`
  because a website's own application code never observes raw TCP/UDP
  packets. Detecting those attack types for real requires packet-level
  capture (Scapy/tcpdump) sitting in front of the TCP stack — a genuinely
  different, lower-level piece of infrastructure, and it's why this
  remains future work rather than something bolted on here.
- **What this genuinely can detect**: HTTP-flood-style application-layer
  abuse — a real, meaningful subset of DDoS attacks (this is the same
  class Slowloris and HTTP floods belong to).

### How to generate real test traffic (against your own deployment only)

Never point load-testing tools at a site you don't own. Against your own
deployed URL:

```bash
# Apache Bench
ab -n 3000 -c 100 https://your-app.onrender.com/shop/

# hey (friendlier output)
hey -n 3000 -c 100 https://your-app.onrender.com/shop/
```

Detection requires a genuinely high sustained rate — the model was
trained on synthetic http_flood traffic averaging ~2,500 requests/sec, so
a single `ab`/`hey` process may or may not cross that threshold depending
on your network and Render's single-worker free-tier limits. Watch the
dashboard's live feed while the test runs; if a 🌐-marked entry shows
`http_flood`, the real detection pipeline just fired for genuine reasons,
not a canned demo.

## Deploying to a public URL (so anyone can open it in a browser)

This project is now deployment-ready for free cloud hosting — the `Procfile`,
`render.yaml`, and `requirements.txt` (with `gunicorn` added) are already
set up. I can't create a hosting account or push code on your behalf (no
internet access on my side, and account creation is tied to your email
anyway), but here's exactly what to do — about 5 minutes total.

### Option A — Render (recommended, supports render.yaml auto-config)

1. Go to **[render.com](https://render.com)** and sign up (free, no credit
   card required for the free tier).
2. Put this project on GitHub first: create a new repository at
   **[github.com/new](https://github.com/new)**, then either drag-and-drop
   the unzipped `ddos_project` folder into GitHub's web upload, or push it
   with git if you're comfortable with the command line.
3. Back in Render: **New +** → **Web Service** → connect your GitHub
   account → select the repository you just created.
4. Render will detect `render.yaml` automatically and pre-fill the build
   and start commands — just click **Create Web Service**.
5. Wait 2–3 minutes for the first build. You'll get a live URL like
   `https://shieldchain-xxxx.onrender.com` — that's your public dashboard.

Note: Render's free tier "sleeps" after 15 minutes of inactivity and takes
~30–60 seconds to wake back up on the next visit — fine for a demo, just
give it a moment to load if it's been idle.

### Option B — PythonAnywhere (no GitHub required, direct file upload)

1. Sign up free at **[pythonanywhere.com](https://www.pythonanywhere.com)**.
2. Go to the **Files** tab and upload the unzipped `ddos_project` folder
   (or upload the zip and unzip it in their in-browser console).
3. Go to the **Web** tab → **Add a new web app** → choose **Flask** →
   point it at `app.py` in your uploaded folder.
4. In the **Consoles** tab, open a Bash console and run:
   ```
   pip install --user -r ddos_project/requirements.txt
   ```
5. Click **Reload** on the Web tab. Your app is live at
   `https://yourusername.pythonanywhere.com`.

### After it's live

Anyone with the URL can open the dashboard in a normal browser — no Python
or installation needed on their end, unlike the desktop/exe version. This
is the easiest way to demo the project to your guide or examiner from
your phone.

## Building a Windows .exe

A double-click `.exe` needs to be compiled on Windows itself (PyInstaller
doesn't cross-compile from Linux/Mac to Windows), so build it there:

1. Copy this whole `ddos_project` folder to a Windows machine with
   Python 3.10+ installed (get it from python.org — check "Add to PATH"
   during install).
2. Double-click **`build_exe.bat`**. It installs the dependencies and
   PyInstaller, then builds the executable.
3. When it finishes, find **`dist\ShieldChain.exe`**. Double-click it —
   it starts the server and opens the dashboard in your default browser
   automatically. A console window stays open showing server logs; closing
   it stops the server.

The `.exe` is fully self-contained (models, dataset, templates, and the
`ml`/`blockchain` modules are all bundled in) — you can copy just that one
file to another Windows machine without Python installed and it will still
run.

If you'd rather test without building an exe, `python run.py` gives you
the exact same auto-launching behavior (server + auto-opened browser tab).

## Extending this for a stronger submission

- Swap `data/generate_traffic.py`'s output for a real CICDDoS2019 CSV
  (same column names) and retrain — this gives you defensible, citable
  accuracy/precision/recall numbers instead of near-100% synthetic results.
- Deploy `smart_contract.sol` on a local Ganache network and swap
  `blockchain/smart_contract.py`'s calls for Web3.py calls to the deployed
  contract, to demonstrate an actual on-chain deployment.
- Add an LSTM-based time-series model alongside the Random Forest, per the
  Future Scope section of the report.
