# 🔍 Port Scan Detector

A Python desktop tool that detects **network reconnaissance** (MITRE ATT&CK **T1046: Network Service Discovery**) in firewall logs. It finds IP addresses that probe many ports or hosts in a short time, classifies the scan, scores its severity, and exports alerts in **SIEM-friendly JSON**.

Built as a blue-team / SOC learning project.

![Dashboard](docs/screenshot.png)

---

## ✨ Features

- **Sliding-window detection**: alert when one IP touches at least *N* distinct ports or hosts within *S* seconds (default: 10 in 10 seconds, adjustable in the UI)
- **Scan pattern**: vertical scan (one host, many ports), horizontal sweep (one port, many hosts), block scan
- **Scan technique**: SYN, NULL, FIN, XMAS, or connect/mixed scans, identified from TCP flags
- **Open-port insight**: shows which scanned ports were *accepted* by the firewall (actually exposed)
- **Sensitive-port awareness**: SSH, RDP, SMB, databases and similar ports raise the severity
- **Severity levels**: `MEDIUM`, `HIGH`, `CRITICAL`, plus an overall threat level
- **Recommended response** for every alert
- **Charts**: top scanner IPs and most targeted ports
- **Export**: CSV for reports, JSON (one object per line) for Splunk / ELK / Wazuh
- **Sample log generator**: includes normal users and a low-and-slow visitor to show there are no false alarms

---

## 🖥️ How it works

```
firewall log → log_parser → detector (sliding window per source IP) → alerts → dashboard / CSV / JSON
```

1. Load a firewall log or click **Generate Sample Log**
2. Set the rule (distinct ports/hosts and time window)
3. Click **RUN DETECTION**
4. Select an alert to see details and the recommended response

---

## 📁 Project structure

```
port_scan_detector/
├── main.py               # dashboard (Tkinter GUI), charts, exports
├── detector.py           # detection engine, scan classification, severity
├── log_parser.py         # parses firewall log lines
├── sample_generator.py   # creates test traffic
├── requirements.txt
├── data/                 # logs (the sample log is generated here)
└── output/               # exported CSV / JSON
```

---

## 🚀 Getting started

```bash
git clone https://github.com/sohailahmad-sec/port-scan-detector.git
cd port-scan-detector
pip install -r requirements.txt
python main.py
```

Click **Generate Sample Log**, then **RUN DETECTION**.

> Tkinter ships with Python on Windows and macOS. On Debian/Ubuntu install it with `sudo apt install python3-tk`.

---

## 📄 Log format

One event per line:

```
2026-10-11 22:18:23 DROP SRC=45.1.2.3 DST=192.168.1.10 PROTO=TCP SPT=44321 DPT=22 FLAGS=S
```

| Field | Meaning |
|---|---|
| time | `YYYY-MM-DD HH:MM:SS` |
| action | `DROP`, `ACCEPT`, `ALLOW`, ... |
| SRC / DST | source and destination IP |
| PROTO | `TCP` or `UDP` |
| SPT / DPT | source (optional) and destination port |
| FLAGS | TCP flags such as `S`, `F`, `FPU`, or `NONE` |

Lines that do not match are skipped. Firewall logs in another format need a small conversion step first.

---

## 🧪 Sample results

Running the built-in sample log gives:

| Severity | Source IP | Type | Notes |
|---|---|---|---|
| CRITICAL | 45.155.205.12 | Vertical scan (SYN) | 50 ports in about 3 seconds; ports 22 and 80 were open |
| HIGH | 91.240.118.5 | Vertical scan (XMAS) | evasive flag combination |
| HIGH | 185.220.101.9 | Horizontal sweep (SYN) | port 445 (SMB) across 20 hosts |

Normal visitors and a slow visitor that touches only 4 ports do **not** trigger an alert.

---

## 📤 SIEM export

**Export JSON** writes one JSON object per line, ready to ingest into Splunk, ELK or Wazuh:

```json
{"sourcetype": "port_scan_alert", "severity": "CRITICAL", "src_ip": "45.155.205.12", "scan_type": "Vertical scan (SYN scan)", "unique_ports": 50, "mitre": "T1046 - Network Service Discovery"}
```
(shortened example)

---

## ⚠️ Limitations

- A slow scan (for example one port every 11 seconds) can stay under the 10-second window
- A distributed scan from many IPs can keep each IP under the threshold
- Works on the log format above only; it does not block anything automatically
- The source IP may belong to a VPN or proxy

## 🗺️ Roadmap

- [ ] Second, longer detection window for slow scans
- [ ] Correlate scans from many IPs (botnet-style)
- [ ] IP reputation lookup (AbuseIPDB)
- [ ] Automatic blocking and email / Telegram alerts
- [ ] Combine with SSH brute-force detection to catch the full attack chain

---

## 🛠️ Tech

Python · Tkinter · Matplotlib

## ⚖️ Disclaimer

For **learning and authorized use only**. Analyze logs from networks you own or are permitted to monitor.

## 👤 Author

**Sohail Ahmad**
Aspiring SOC Analyst | Python | Log Analysis & Threat Detection
GitHub: [@sohailahmad-sec](https://github.com/sohailahmad-sec)
