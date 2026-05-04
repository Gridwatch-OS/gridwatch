# 🛡️ Gridwatch

<div align="center">

![Gridwatch Banner](https://img.shields.io/badge/Gridwatch-Network%20Security%20Platform-blue?style=for-the-badge&logo=shield&logoColor=white)

**A Multi-Engine Automated Network Security Platform**

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=flat-square)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-blue.svg?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey.svg?style=flat-square)]()
[![Contributors](https://img.shields.io/badge/Contributors-6-orange.svg?style=flat-square)]()

[Features](#-features) • [How It Works](#-how-it-works) • [Getting Started](#-getting-started) • [Dashboard](#-dashboard-preview) • [Contributors](#-contributors) • [Roadmap](#-roadmap)

</div>

---

## 📋 Project Overview

**Gridwatch** is a multi-engine automated network security platform built by a team of 6 contributors. Designed for nonprofits, small businesses, and security-conscious organizations, Gridwatch provides enterprise-grade security monitoring without the enterprise price tag.

The platform runs **four core engines simultaneously**, providing comprehensive protection through:
- Live threat intelligence integration
- Continuous network monitoring
- Multi-engine antivirus scanning
- Real-time RAT and spyware detection

Gridwatch runs as an automated background service on both **Windows** and **Linux**, requiring zero manual intervention once deployed.

---

## ✨ Features

### 🔥 Engine 1: Threat Intelligence Aggregator
- Pulls live malicious IP lists every night from **EmergingThreats**, **AbuseIPDB**, and **FireHOL**
- Deduplicates entries into one master blocklist
- Automatically pushes updates to the firewall
- **Zero manual intervention required**

### 🌐 Engine 2: Network Discovery & Monitoring
- Scans the entire local network subnet
- Maps every device by:
  - IP Address
  - MAC Address
  - Open Ports
  - Device Type
- **Flags new or unknown devices** not present in previous scans
- Historical tracking for device baseline comparison

### 🦠 Engine 3: Multi-Engine Antivirus
- Runs **multiple open source AV scanners simultaneously**
- Scans active files and processes in real-time
- Multi-engine approach ensures: *if one misses a threat, another catches it*
- Supported engines: [ClamAV, YARA Rules, [Additional Engines TBD]]

### 🎯 Engine 4: RAT Watch & Connection Monitor
- Monitors all outbound connections in **real-time**
- Detects Remote Access Trojans (RATs) and spyware
- Flags processes making unauthorized connections
- Cross-references against live threat intel blocklist
- Automatic alerting on suspicious activity

---

## 🔧 How It Works

```
┌─────────────────────────────────────────────────────────────────────┐
│                         GRIDWATCH ENGINE                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   ┌──────────────┐    ┌──────────────┐    ┌──────────────┐          │
│   │   Engine 1   │    │   Engine 2   │    │   Engine 3   │          │
│   │  Threat Intel│    │Network Scanner│   │  Multi-AV    │          │
│   └──────┬───────┘    └──────┬───────┘    └──────┬───────┘          │
│          │                   │                   │                   │
│          └───────────────────┼───────────────────┘                   │
│                              │                                       │
│                    ┌─────────▼─────────┐                             │
│                    │   Engine 4        │                             │
│                    │   RAT Watch       │                             │
│                    │   Connection Mon. │                             │
│                    └─────────┬─────────┘                             │
│                              │                                       │
│              ┌───────────────┼───────────────┐                       │
│              ▼               ▼               ▼                       │
│      ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
│      │  Dashboard  │  │   Alerts    │  │   Reports   │              │
│      └─────────────┘  └─────────────┘  └─────────────┘              │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Execution Flow

1. **Initialize** - Load configuration and verify dependencies
2. **Fetch Threat Intel** - Download and merge malicious IP lists
3. **Network Scan** - Discover all devices on local subnet
4. **Process Analysis** - Check running processes against blocklist
5. **AV Scan** - Run multi-engine scans on active files
6. **Generate Report** - Output dashboard, alerts, and reports

---

## 🏗️ Architecture

```
gridwatch/
├── gridwatch.py           # Main entry point and orchestrator
├── blocklist.txt          # Generated malicious IP blocklist
├── discovered_devices.txt # Network device inventory
├── config/
│   └── [settings.yaml]    # Configuration file
├── engines/
│   ├── [threat_intel.py]  # Engine 1: Threat intelligence
│   ├── [network_scan.py]  # Engine 2: Network discovery
│   ├── [multi_av.py]      # Engine 3: Antivirus integration
│   └── [rat_watch.py]     # Engine 4: Connection monitor
├── reports/
│   └── [report_generator.py]  # PDF report generation
└── utils/
    └── [helpers.py]       # Shared utilities
```

*Items in [brackets] are planned for future releases*

---

## 📊 Dashboard Preview

```
╔════════════════════════════════════════════════════════════╗
║                                                            ║
║         GRIDWATCH - Network Security Monitor               ║
║               Dashboard v1.0.0                             ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝

┌────────────────────────────────────────────────────────────┐
│  📡 NETWORK STATUS                                         │
├────────────────────────────────────────────────────────────┤
│  Devices Online:        24                                 │
│  New Devices:           0                                  │
│  Unknown Devices:       0                                  │
└────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────┐
│  🛡️ THREAT INTELLIGENCE                                    │
├────────────────────────────────────────────────────────────┤
│  Blocked IPs:           145,892                            │
│  Last Update:           2026-05-03 21:00:00                │
│  Sources:               3 (FireHOL, AbuseIPDB, ET)         │
└────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────┐
│  🦠 ANTIVIRUS STATUS                                        │
├────────────────────────────────────────────────────────────┤
│  Engines Active:        [ClamAV ✓] [YARA ✓]                │
│  Last Scan:             2026-05-03 20:45:00                │
│  Threats Found:         0                                  │
└────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────┐
│  🎯 RAT WATCH                                               │
├────────────────────────────────────────────────────────────┤
│  Connections Monitored: 156                                │
│  Suspicious:            0                                  │
│  Status:                ✓ All Clear                        │
└────────────────────────────────────────────────────────────┘

  Last Run: 2026-05-03 21:30:00
```

---

## 🚨 Alert Example

When Gridwatch detects a threat, it generates detailed alerts:

```
════════════════════════════════════════════════════════════════
⚠️  GRIDWATCH SECURITY ALERT
════════════════════════════════════════════════════════════════

Alert Type:       Suspicious Outbound Connection
Severity:         HIGH
Timestamp:        2026-05-03 21:32:15

┌─ PROCESS DETAILS ─────────────────────────────────────────────
│  Process Name:   suspicious_app.exe
│  PID:            4832
│  Path:           C:\Users\[user]\AppData\Local\Temp\suspicious_app.exe
│  User:           DESKTOP-ABC\Administrator
└───────────────────────────────────────────────────────────────

┌─ CONNECTION DETAILS ──────────────────────────────────────────
│  Destination IP:    185.234.XX.XX
│  Destination Port:  443
│  Protocol:          TCP
│  Connection State:  ESTABLISHED
└───────────────────────────────────────────────────────────────

┌─ THREAT INTEL MATCH ──────────────────────────────────────────
│  Source:         FireHOL Level 1
│  Category:       Known C2 Server
│  First Seen:     2026-04-15
│  Confidence:     HIGH
└───────────────────────────────────────────────────────────────

┌─ ACTION TAKEN ────────────────────────────────────────────────
│  ✓ Connection logged
│  ✓ Process flagged for review
│  ⚠ Manual intervention recommended
└───────────────────────────────────────────────────────────────

┌─ RECOMMENDED NEXT STEPS ──────────────────────────────────────
│  1. Terminate process: taskkill /PID 4832 /F
│  2. Quarantine file for analysis
│  3. Scan system with full AV scan
│  4. Check for persistence mechanisms
│  5. Review user activity logs
└───────────────────────────────────────────────────────────────

════════════════════════════════════════════════════════════════
```

---

## 📄 Report Generation

Gridwatch includes a professional PDF report generator designed for **executive handoff**. Perfect for presenting security status to nonprofit boards or small business directors.

### Report Contents:
- **Security Score** (0-100 with letter grade)
- **Executive Summary**
- **Network Inventory** (all discovered devices)
- **Threat Findings** (ranked by severity)
- **Recommended Fixes** (prioritized action items)
- **Scan History** (trend analysis)

### Generate a Report:
```bash
python gridwatch.py --report
```

*[PDF report generation coming in v2.0]*

---

## 👥 Contributors

<table>
  <tr>
    <td align="center">
      <a href="[GitHub Profile URL]">
        <img src="https://via.placeholder.com/100" width="100px;" alt=""/>
        <br /><sub><b>[Contributor 1]</b></sub>
      </a>
      <br />
      <sub>Engine 1: Threat Intel</sub>
    </td>
    <td align="center">
      <a href="[GitHub Profile URL]">
        <img src="https://via.placeholder.com/100" width="100px;" alt=""/>
        <br /><sub><b>[Contributor 2]</b></sub>
      </a>
      <br />
      <sub>Engine 2: Network Scanner</sub>
    </td>
    <td align="center">
      <a href="[GitHub Profile URL]">
        <img src="https://via.placeholder.com/100" width="100px;" alt=""/>
        <br /><sub><b>[Contributor 3]</b></sub>
      </a>
      <br />
      <sub>Engine 3: Multi-AV</sub>
    </td>
  </tr>
  <tr>
    <td align="center">
      <a href="[GitHub Profile URL]">
        <img src="https://via.placeholder.com/100" width="100px;" alt=""/>
        <br /><sub><b>[Contributor 4]</b></sub>
      </a>
      <br />
      <sub>Engine 4: RAT Watch</sub>
    </td>
    <td align="center">
      <a href="[GitHub Profile URL]">
        <img src="https://via.placeholder.com/100" width="100px;" alt=""/>
        <br /><sub><b>[Contributor 5]</b></sub>
      </a>
      <br />
      <sub>Dashboard & Reports</sub>
    </td>
    <td align="center">
      <a href="[GitHub Profile URL]">
        <img src="https://via.placeholder.com/100" width="100px;" alt=""/>
        <br /><sub><b>[Contributor 6]</b></sub>
      </a>
      <br />
      <sub>Integration & DevOps</sub>
    </td>
  </tr>
</table>

---

## 🚀 Getting Started

### Prerequisites

- **Python 3.8+**
- **Administrator/Root privileges** (for network scanning)
- **Windows**: Npcap (for ARP scanning) - [Download here](https://npcap.com/)
- **Linux**: libpcap-dev

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/Gridwatch-OS/gridwatch.git
   cd gridwatch
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```
   
   Or install manually:
   ```bash
   pip install requests scapy psutil
   ```

3. **Run Gridwatch**
   ```bash
   # Windows (run as Administrator)
   python gridwatch.py
   
   # Linux (run as root)
   sudo python3 gridwatch.py
   ```

### Quick Test
```bash
# Run a quick scan
python gridwatch.py

# Check output files
cat blocklist.txt
cat discovered_devices.txt
```

---

## 📍 Roadmap

### ✅ Phase 1: Base Model (Current)
- [x] Threat intel fetching (FireHOL)
- [x] Local network scanning (ARP + Ping)
- [x] Process connection analysis
- [x] Terminal summary output
- [x] Cross-platform support

### 🔄 Phase 2: Engine Expansion
- [ ] Multiple threat intel sources (AbuseIPDB, EmergingThreats)
- [ ] Automated blocklist deduplication
- [ ] Device type fingerprinting
- [ ] New device detection alerts
- [ ] Multi-AV integration (ClamAV)

### 📅 Phase 3: Automation & Reporting
- [ ] Background service mode
- [ ] Scheduled scans
- [ ] PDF report generation
- [ ] Email alerts
- [ ] Historical trend tracking

### 🔮 Phase 4: Enterprise Features
- [ ] Web dashboard
- [ ] Multi-site monitoring
- [ ] API integrations
- [ ] Custom rule engine
- [ ] SIEM integration

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🤝 Contributing

We welcome contributions! Gridwatch is designed with a modular architecture so team members can work independently on their assigned engines.

### How to Contribute

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/engine-improvement`)
3. Commit your changes (`git commit -m 'Add new threat intel source'`)
4. Push to the branch (`git push origin feature/engine-improvement`)
5. Open a Pull Request

### Contribution Guidelines

- Follow the existing code style and commenting conventions
- Add docstrings to all functions
- Test on both Windows and Linux when possible
- Update documentation as needed

---

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/Gridwatch-OS/gridwatch/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Gridwatch-OS/gridwatch/discussions)

---

<div align="center">

**Built with ❤️ by the Gridwatch Team**

*Protecting networks, one scan at a time.*

</div>
