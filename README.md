<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=32&duration=2800&pause=2000&color=00FF9C&center=true&vCenter=true&width=940&lines=DPI+Engine+%E2%80%94+Deep+Packet+Inspection+System;Built+from+scratch+in+Python+%F0%9F%90%8D;Live+Dashboard+%2B+ML+Classifier+%F0%9F%A4%96;by+Aditya+Pandey" alt="Typing SVG" />

<br/>

![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.1-000000?style=for-the-badge&logo=flask&logoColor=white)
![scikit-learn](https://img.shields.io/badge/scikit--learn-1.8-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-2.7-4B8BBE?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)
![Completion](https://img.shields.io/badge/Completion-90%25-00FF9C?style=for-the-badge)

<br/>

> **A fully functional Deep Packet Inspection engine built entirely from scratch in Python.**  
> Raw byte parsing · TLS SNI extraction · ML traffic classification · Live web dashboard  

<br/>

**[🚀 Quick Start](#-quick-start) · [📊 Dashboard](#-live-dashboard) · [🤖 ML Classifier](#-ml-classifier) · [🏗️ Architecture](#️-architecture) · [📈 Completion Status](#-project-completion-status)**

</div>

---

## 🔥 What Is This?

This is a **production-grade Deep Packet Inspection (DPI) engine** — the same technology used by ISPs, enterprise firewalls, and network security products like Wireshark, Snort, and Zeek — but built **100% from scratch in Python** by a CSE student.

It captures live network traffic, tears apart every packet at the **raw byte level** (Ethernet → IP → TCP/UDP → Payload), extracts domain names from **encrypted HTTPS traffic** using TLS SNI, classifies traffic into 50+ known apps, applies configurable block/allow rules, and visualizes everything on a **real-time web dashboard**.

> **The key insight:** Even "encrypted" HTTPS traffic reveals the target domain in the very first packet (TLS Client Hello → SNI extension) — **in plain text, before encryption starts.** This project exploits exactly that.

---

## ✨ Features

| Feature | Details | Status |
|---|---|---|
| 🔬 **Zero-dependency packet parsing** | Raw byte parsing with Python `struct` — no Scapy for core | ✅ Complete |
| 🔐 **TLS SNI Extraction** | Navigates TLS 1.2/1.3 Client Hello structure byte-by-byte | ✅ Complete |
| 📱 **App Classification** | Identifies 50+ apps: YouTube, Netflix, WhatsApp, TikTok, GitHub... | ✅ Complete |
| ⚖️ **Rule Engine** | Tiered block/allow rules: by App · Domain · IP · Port | ✅ Complete |
| 🖥️ **Live Web Dashboard** | Real-time UI — packet counter, flow table, app breakdown, event log | ✅ Complete |
| 📡 **Live Packet Capture** | Sniffs live traffic from any network interface via Scapy | ✅ Complete |
| 🤖 **ML Traffic Classifier** | Random Forest — classifies traffic by behavioral features | ✅ Complete |
| 📁 **PCAP File Analysis** | Analyze saved Wireshark `.pcap` captures | ✅ Complete |
| 📊 **Report Export** | One-click download of full analysis report | ✅ Complete |
| 🔄 **Hot Rule Updates** | Add block rules live via API — no restart needed | ✅ Complete |
| 🧹 **Memory Management** | Auto stale-flow cleanup, O(1) deque buffer | ✅ Complete |
| 🧪 **Test Suite** | 12 backend tests covering all components | ✅ Complete |

---

## 📈 Project Completion Status

```
Overall Completion: ████████████████████░░  90%
```

| Component | Completion | Notes |
|---|---|---|
| Core packet parser | 100% | Handles Ethernet/IPv4/TCP/UDP |
| TLS SNI extractor | 100% | TLS 1.2 + 1.3, HTTP Host fallback |
| App classifier | 100% | 50+ apps, 3-tier matching |
| Rule engine | 100% | App/Domain/IP/Port rules |
| Connection tracker | 100% | Flow state + stale cleanup |
| ML classifier | 100% | Random Forest, 12 classes, 4150 samples |
| Flask REST API | 100% | 10 endpoints, all tested |
| Live dashboard UI | 95% | All panels working |
| Live capture | 85% | Works on open networks; college proxies hide SNI |
| PCAP analysis | 100% | Full pipeline tested |
| Demo mode | 100% | Works offline, no PCAP needed |

### ⚠️ Known Limitation (5%)
On **corporate/college networks** that route all HTTPS traffic through a transparent proxy (DNS-over-HTTPS / SSL inspection), the TLS Client Hello never reaches the capture interface directly — so SNI shows as "Unknown." This is not a bug in the engine; it's a network environment constraint that affects **all** real-world DPI tools including Wireshark and Zeek on proxied networks. On home/open WiFi, full app detection works correctly.

---

## 🚀 Quick Start

### Prerequisites
- Python 3.9+
- Windows: [Npcap](https://npcap.com/#download) (for live capture)
- Linux/Mac: `sudo` for live capture

```bash
# 1. Clone the repo
git clone https://github.com/YOUR_USERNAME/dpi-engine.git
cd dpi-engine

# 2. Create virtual environment
python -m venv venv

# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run offline demo (no setup, works instantly)
python main.py --demo

# 5. Launch live dashboard
python run_dashboard.py
# → Open http://localhost:5000
```

---

## 🖥️ Live Dashboard

```bash
python run_dashboard.py
```

Open **[http://localhost:5000](http://localhost:5000)** in your browser.

**Dashboard panels:**
- 📦 **Stats bar** — Packets inspected / Allowed / Blocked / Block rate / Active flows
- 🌊 **Live Flow Table** — Every connection: decision, app, SNI domain, source/dest IPs, ML prediction
- 📊 **App Breakdown** — Traffic distribution bar chart per app
- 📋 **Event Log** — Real-time log of capture events
- 🤖 **ML Classifier** — Behavioral predictions for active flows
- 📥 **Export Report** — Download full analysis as `.txt`

---

## 💻 CLI Usage

```bash
# Offline demo — see blocking in action instantly
python main.py --demo

# Analyze a PCAP file
python main.py --pcap capture.pcap

# Analyze with custom block rules
python main.py --pcap capture.pcap --block YouTube TikTok Facebook

# Block specific domains
python main.py --pcap capture.pcap --block-domains ads.doubleclick.net tracking.com

# Block ports (e.g. BitTorrent)
python main.py --pcap capture.pcap --block-ports 6881 6882

# Verbose output (every packet)
python main.py --pcap capture.pcap --verbose

# Save report to file
python main.py --pcap capture.pcap --report my_report.txt
```

**Demo output:**
```
  Domain                              App                  Decision
  ──────────────────────────────────────────────────────────────────
  www.youtube.com                     YouTube              🚫 BLOCK
  api.github.com                      GitHub               ✅ ALLOW
  web.whatsapp.com                    WhatsApp             ✅ ALLOW
  www.tiktok.com                      TikTok               🚫 BLOCK
  www.instagram.com                   Instagram            ✅ ALLOW
  ads.doubleclick.net                 Unknown              🚫 BLOCK
  teams.microsoft.com                 MS Teams             ✅ ALLOW
  discord.com                         Discord              ✅ ALLOW
  www.netflix.com                     Netflix              ✅ ALLOW
  api.anthropic.com                   Anthropic/Claude     ✅ ALLOW
```

---

## 🤖 ML Classifier

The ML layer classifies traffic **even when SNI is unavailable** — using behavioral features instead of domain names. This is how enterprise DPI products handle QUIC, DoH, and CDN-masked traffic.

```bash
python ml/ml_classifier.py
```

**Model:** Random Forest (100 trees, depth 8)  
**Training data:** 4,150 synthetic samples  
**Classes:** YouTube · Netflix · WhatsApp · Instagram · Facebook · GitHub · Zoom · Discord · TikTok · General Web · File Transfer · Unknown

**Feature importance:**
```
byte_count          ████████████████████  most important
avg_pkt_size        ████████████████
dst_port            ████████████
packet_count        ████████
byte_per_packet     ██████
protocol            ████
is_https            ███
```

**Why Random Forest and not a neural network?**  
For structured tabular features (port numbers, byte counts, packet sizes), tree-based models consistently outperform neural networks — while being 100x faster at inference and fully interpretable. This is a deliberate engineering choice, not a limitation.

---

## 🏗️ Architecture

```
Raw Packet (bytes)
       │
  ┌────▼────────────────────────────────────────────────┐
  │  PCAPReader / Scapy                                  │
  │  Read bytes from .pcap file or live interface        │
  └────┬────────────────────────────────────────────────┘
       │
  ┌────▼────────────────────────────────────────────────┐
  │  PacketParser                                        │
  │  Ethernet (14B) → IPv4 (20B) → TCP/UDP → Payload    │
  └────┬────────────────────────────────────────────────┘
       │
  ┌────▼────────────────────────────────────────────────┐
  │  SNIExtractor                                        │
  │  TLS Record → Handshake → ClientHello → Extensions  │
  │  → SNI Extension (type 0x0000) → hostname           │
  └────┬────────────────────────────────────────────────┘
       │
  ┌────▼────────────────────────────────────────────────┐
  │  AppClassifier                                       │
  │  Exact match → Suffix match → 50+ known apps        │
  └────┬────────────────────────────────────────────────┘
       │
  ┌────▼────────────────────────────────────────────────┐
  │  RuleManager                                         │
  │  IP → App → Domain → Port → Default (tiered eval)   │
  └────┬────────────────────────────────────────────────┘
       │
  ┌────▼────────────────────────────────────────────────┐
  │  ConnectionTracker                                   │
  │  FlowKey (5-tuple) → FlowState → Fast-path cache    │
  └────┬────────────────────────────────────────────────┘
       │
  ┌────▼────────────────────────────────────────────────┐
  │  MLClassifier (parallel)                             │
  │  Random Forest → App prediction + confidence %      │
  └────┬────────────────────────────────────────────────┘
       │
  ┌────▼────────────────────────────────────────────────┐
  │  Flask Dashboard                                     │
  │  REST API → Live UI → Export                        │
  └─────────────────────────────────────────────────────┘
```

---

## 📁 Project Structure

```
dpi-engine/
├── 📄 main.py                    # CLI entry point
├── 📄 run_dashboard.py           # One-click dashboard launcher
├── 📄 live_capture.py            # Standalone live capture module
├── 📄 requirements.txt
│
├── 📂 src/                       # Core DPI engine (zero external deps)
│   ├── types.py                  # FlowKey · ParsedPacket · DPIDecision
│   ├── pcap_reader.py            # Binary PCAP parser (pure struct)
│   ├── packet_parser.py          # Ethernet/IP/TCP/UDP byte dissector
│   ├── sni_extractor.py          # TLS Client Hello SNI extractor
│   ├── app_classifier.py         # Domain → App classifier (50+ apps)
│   ├── rule_manager.py           # Tiered block/allow rule engine
│   ├── connection_tracker.py     # Flow state manager + cleanup
│   └── dpi_engine.py             # Main orchestrator
│
├── 📂 ml/
│   └── ml_classifier.py          # Random Forest traffic classifier
│
├── 📂 dashboard/
│   ├── dashboard_server.py       # Flask REST API (10 endpoints)
│   └── templates/
│       └── index.html            # Live dashboard UI
│
└── 📂 tests/
    └── test_components.py        # 12 unit tests
```

---

## 🔌 REST API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/` | Dashboard UI |
| GET | `/api/stats` | Live stats + recent flows |
| GET | `/api/interfaces` | Available network interfaces |
| POST | `/api/start` | Start live capture |
| POST | `/api/stop` | Stop live capture |
| GET | `/api/ml_predict` | Run ML classifier on flows |
| GET | `/api/report` | Download analysis report |
| POST | `/api/clear` | Reset all state |
| GET | `/api/rules` | View current blocking rules |
| POST | `/api/rules/block_app` | Hot-add blocked app |
| POST | `/api/rules/block_domain` | Hot-add blocked domain |

---

## 🛠️ Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| Core engine | Pure Python + `struct` | Zero-dependency packet parsing |
| Live capture | Scapy 2.7 | Raw packet sniffing |
| ML | scikit-learn · numpy | Random Forest classifier |
| Web server | Flask 3.1 | REST API + dashboard |
| Frontend | HTML/CSS/JS | Real-time dashboard UI |

---

## 🧪 Run Tests

```bash
python tests/test_components.py
```

```
[1]  Imports .......................... OK
[2]  inspect(None) guard .............. OK
[3]  App classification + rules ....... OK
[4]  recent_flows deque ............... OK
[5]  is_capturing thread safety ........ OK
[6]  Stale flow cleanup ............... OK
[7]  app_name variable shadowing ....... OK
[8]  ML classifier + pkl recovery ...... OK
[9]  All Flask API endpoints ........... OK
[10] Hot rule update .................. OK
[11] SNI extractor edge cases .......... OK
[12] DPIEngine.reset() ................ OK

ALL 12 TESTS PASSED ✓
```

---

## 🗺️ Roadmap

- [x] Raw packet parsing from scratch
- [x] TLS SNI extraction
- [x] App classification (50+ apps)
- [x] Block/allow rule engine
- [x] Live web dashboard
- [x] ML traffic classifier
- [x] PCAP analysis mode
- [x] REST API with 10 endpoints
- [x] Hot rule updates (no restart)
- [ ] QUIC / HTTP3 SNI extraction
- [ ] Real-time alerts (email/webhook on block events)
- [ ] Train ML on real labeled PCAP datasets (CICIDS, ISCX)
- [ ] Per-user traffic quotas
- [ ] Docker containerization

---

## 👤 About the Author

**Aditya Pandey**  
Computer Science Engineering · AI & Machine Learning Specialization

> *"I believe in understanding systems from the ground up — not just using libraries, but knowing what they do underneath. This project is that principle applied to networking and ML together."*

[![GitHub](https://img.shields.io/badge/GitHub-Follow-181717?style=for-the-badge&logo=github)](https://github.com/Adityamax0)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0A66C2?style=for-the-badge&logo=linkedin)](https://linkedin.com/in/aditya-pandey-ai-ml)

---

## 📄 License

MIT License — free to use, modify, and distribute with attribution.

---

<div align="center">

**Built with 🐍 Python · 🧠 ML · ❤️ and Claude (Anthropic AI)**

*If this project helped you, please ⭐ star the repo!*

</div>
