<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d1117,50:1a1f2e,100:0d1117&height=200&section=header&text=GRIDWATCH&fontSize=80&fontColor=00d4ff&fontAlignY=38&desc=Open%20Source%20Network%20Security%20Platform&descAlignY=60&descColor=8b9ab0&animation=fadeIn" width="100%"/>

<br/>

[![License: MIT](https://img.shields.io/badge/License-MIT-00d4ff.svg?style=for-the-badge)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.8+-1a1f2e.svg?style=for-the-badge&logo=python&logoColor=00d4ff)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-1a1f2e.svg?style=for-the-badge&logo=linux&logoColor=00d4ff)]()
[![Status](https://img.shields.io/badge/Status-Active%20Development-1a1f2e.svg?style=for-the-badge&logo=github&logoColor=00d4ff)]()
[![Contributors](https://img.shields.io/badge/Contributors-6-1a1f2e.svg?style=for-the-badge&logo=github&logoColor=00d4ff)]()

<br/>

> **Automated multi-engine network security — threat intelligence, device discovery, RAT detection, and AV scanning. Built by engineers, for everyone.**

<br/>

[Features](#-features) &nbsp;•&nbsp; [How It Works](#-how-it-works) &nbsp;•&nbsp; [Dashboard](#-dashboard-preview) &nbsp;•&nbsp; [Getting Started](#-getting-started) &nbsp;•&nbsp; [Team](#-team) &nbsp;•&nbsp; [Roadmap](#-roadmap)

</div>

---

## 👥 Team

<div align="center">

| | Name | Role | GitHub |
|:---:|:---|:---|:---|
| 🔴 | *To be added* | Engine 1 — Threat Intelligence | — |
| 🟠 | *To be added* | Engine 2 — Network Scanner | — |
| 🟡 | *To be added* | Engine 3 — Multi-AV | — |
| 🟢 | *To be added* | Engine 4 — RAT Watch | — |
| 🔵 | *To be added* | Dashboard & Reports | — |
| 🟣 | *To be added* | Integration & DevOps | — |

</div>

---

## 📋 Overview

**Gridwatch** is a free, open source network security platform built for nonprofits, small businesses, and community organizations that need real protection without enterprise budgets.

Four engines run simultaneously in the background — blocking threats, mapping devices, scanning for malware, and hunting for spyware — all with zero manual intervention after setup.

```
No subscription.  No license fees.  No manual updates.  Just protection.
```

---

## ✨ Features

<table>
<tr>
<td width="50%">

### 🔴 Engine 1 — Threat Intel
Pulls live malicious IP lists nightly from **EmergingThreats**, **AbuseIPDB**, and **FireHOL**. Deduplicates into one master blocklist and pushes directly to your firewall automatically.

</td>
<td width="50%">

### 🟠 Engine 2 — Network Scanner
Maps every device on your subnet by IP, MAC address, open ports, and device type. Flags unknown devices that weren't there yesterday.

</td>
</tr>
<tr>
<td width="50%">

### 🟡 Engine 3 — Multi-AV
Runs multiple open source antivirus engines simultaneously against active files and processes. If one engine misses something, another catches it.

</td>
<td width="50%">

### 🟢 Engine 4 — RAT Watch
Monitors every outbound connection in real time. Detects Remote Access Trojans and spyware by catching processes phoning home to unknown IPs.

</td>
</tr>
</table>

---

## 🔧 How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                        GRIDWATCH CORE                           │
│                                                                 │
│   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
│   │  Engine 1   │  │  Engine 2   │  │  Engine 3   │            │
│   │ Threat Intel│  │Net Discovery│  │  Multi-AV   │            │
│   └──────┬──────┘  └──────┬──────┘  └──────┬──────┘            │
│          └────────────────┼────────────────┘                    │
│                           │                                     │
│                  ┌────────▼────────┐                            │
│                  │   Engine 4      │                            │
│                  │   RAT Watch     │                            │
│                  └────────┬────────┘                            │
│                           │                                     │
│          ┌────────────────┼────────────────┐                    │
│          ▼                ▼                ▼                    │
│   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
│   │  Dashboard  │  │   Alerts    │  │  PDF Report │            │
│   └─────────────┘  └─────────────┘  └─────────────┘            │
└─────────────────────────────────────────────────────────────────┘
```

**Execution flow:**

1. `Initialize` — Load config, verify dependencies
2. `Fetch Threats` — Pull and merge malicious IP lists
3. `Scan Network` — Discover all devices on subnet
4. `Analyze Processes` — Cross-reference against blocklist
5. `AV Scan` — Multi-engine scan on active files
6. `Output` — Dashboard, alerts, and optional PDF report

---

## 🗂️ Architecture

```
gridwatch/
│
├── gridwatch.py              # Main orchestrator
├── blocklist.txt             # Generated IP blocklist
├── discovered_devices.txt    # Live device inventory
│
├── engines/
│   ├── threat_intel.py       # Engine 1
│   ├── network_scan.py       # Engine 2
│   ├── multi_av.py           # Engine 3
│   └── rat_watch.py          # Engine 4
│
├── reports/
│   └── report_generator.py   # PDF report output
│
├── config/
│   └── settings.yaml         # Configuration
│
└── utils/
    └── helpers.py            # Shared utilities
```

---

## 📊 Dashboard Preview

```
╔══════════════════════════════════════════════════════════╗
║           GRIDWATCH  —  Network Security Monitor         ║
╚══════════════════════════════════════════════════════════╝

  📡 NETWORK
  ─────────────────────────────────────────────────────
  Devices Discovered       127
  New Devices              0
  Unknown Devices          0

  🛡️  THREAT INTELLIGENCE
  ─────────────────────────────────────────────────────
  Malicious IPs Blocked    3,275
  Sources Active           3  (FireHOL · AbuseIPDB · ET)
  Last Update              2026-05-03  03:00:01

  🦠 ANTIVIRUS
  ─────────────────────────────────────────────────────
  Engines Running          ClamAV ✓   YARA ✓
  Last Scan                2026-05-03  02:45:00
  Threats Found            0

  🎯 RAT WATCH
  ─────────────────────────────────────────────────────
  Connections Monitored    156
  Suspicious               0
  Status                   ✓  All Clear

══════════════════════════════════════════════════════════
```

---

## 🚨 Alert Example

```
══════════════════════════════════════════════════════════
  ⚠️  GRIDWATCH SECURITY ALERT  —  HIGH SEVERITY
══════════════════════════════════════════════════════════

  PROCESS
  Name          suspicious_app.exe
  PID           4832
  Path          C:\Users\Admin\AppData\Local\Temp\
  User          DESKTOP-XYZ\Administrator

  CONNECTION
  Destination   185.234.XX.XX : 443
  Protocol      TCP
  State         ESTABLISHED

  THREAT MATCH
  Source        FireHOL Level 1
  Category      Known C2 Server
  Confidence    HIGH

  ACTIONS TAKEN
  ✓  Connection logged
  ✓  Process flagged
  ⚠  Manual review recommended

  NEXT STEPS
  1. taskkill /PID 4832 /F
  2. Quarantine file for analysis
  3. Run full AV scan
  4. Check for persistence mechanisms
  5. Review user activity logs

══════════════════════════════════════════════════════════
```

---

## 📄 Report Generation

Gridwatch generates a professional PDF health report built for **executive handoff** — designed to be handed directly to a nonprofit director or small business owner.

**Report includes:**
- Security score out of 100 with letter grade
- Executive summary in plain language
- Full network device inventory
- Findings ranked by severity
- Prioritized action items with fix instructions

```bash
# Generate a full report
python gridwatch.py --report
```

> PDF generation coming in v2.0

---

## 🚀 Getting Started

### Prerequisites

- Python 3.8+
- Administrator or root privileges
- **Windows:** [Npcap](https://npcap.com/) for ARP scanning
- **Linux:** `libpcap-dev`

### Install

```bash
# Clone the repo
git clone https://github.com/Gridwatch-OS/gridwatch.git
cd gridwatch

# Install dependencies
pip install requests scapy psutil

# Run — Windows (as Administrator)
python gridwatch.py

# Run — Linux (as root)
sudo python3 gridwatch.py
```

### Quick Check

```bash
# View discovered devices
cat discovered_devices.txt

# View blocked IPs
cat blocklist.txt
```

---

## 📍 Roadmap

| Phase | Status | Focus |
|:---|:---:|:---|
| Phase 1 — Base Model | ✅ Done | Threat intel, network scan, process analysis, terminal output |
| Phase 2 — Engine Expansion | 🔄 In Progress | AbuseIPDB, EmergingThreats, ClamAV, device fingerprinting |
| Phase 3 — Automation | 📅 Planned | Background service, scheduled scans, PDF reports, email alerts |
| Phase 4 — Enterprise | 🔮 Future | Web dashboard, multi-site, SIEM integration, API layer |

---

## 🤝 Contributing

Gridwatch is modular by design. Each contributor owns one engine independently.

```bash
# 1. Fork the repo
# 2. Create your branch
git checkout -b feature/your-engine-improvement

# 3. Commit with a clear message
git commit -m "feat(engine-1): add AbuseIPDB source integration"

# 4. Push and open a pull request
git push origin feature/your-engine-improvement
```

**Guidelines:**
- Comment your code clearly — others need to build on it
- Add docstrings to all functions
- Test on Windows and Linux when possible
- Update the README if you change functionality

---

## 📝 License

MIT License — free to use, modify, and distribute. See [LICENSE](LICENSE) for details.

---

<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d1117,50:1a1f2e,100:0d1117&height=120&section=footer&animation=fadeIn" width="100%"/>

**Built by the Gridwatch Team &nbsp;•&nbsp; Protecting networks, one scan at a time.**

</div>
