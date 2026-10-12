"""Port-scan detection engine (sliding window)."""
from collections import defaultdict, deque
from dataclasses import dataclass, asdict

SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
ACCEPT_ACTIONS = {"ACCEPT", "ALLOW", "PASS"}
RISKY_PORTS = {23, 135, 139, 445, 1433, 3389, 5900}  # common worm/ransomware entry points
EVASIVE = ("NULL scan", "FIN scan", "XMAS scan")

SENSITIVE_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 8080: "HTTP-Alt",
}

RESPONSE = {
    "MEDIUM": [
        "Monitor this IP; check AbuseIPDB / whois for reputation.",
        "Confirm the scanned ports are not unnecessarily exposed.",
    ],
    "HIGH": [
        "Block the source IP at the firewall (ufw deny from <IP>).",
        "Review which scanned ports got ACCEPT - those are open to the internet.",
        "Check auth/application logs for follow-up login attempts from this IP.",
    ],
    "CRITICAL": [
        "Block the source IP / subnet immediately.",
        "Close or restrict every port the scanner found open (RDP, SMB, SSH).",
        "Hunt for follow-up exploitation or logins from this IP in other logs.",
        "Escalate to the incident response team and keep evidence (Export CSV/JSON).",
    ],
}


@dataclass
class Alert:
    severity: str
    src_ip: str
    scan_type: str
    unique_ports: int
    unique_hosts: int
    packets: int
    first_seen: str
    last_seen: str
    targets: str
    open_ports: str
    sensitive_ports: str
    mitre: str = "T1046 - Network Service Discovery"

    def to_dict(self):
        return asdict(self)


def _technique(evs):
    tcp = [e for e in evs if e["proto"] == "TCP"]
    if not tcp:
        return "UDP scan"
    flagsets = {e["flags"] for e in tcp}
    if flagsets <= {""}:
        return "NULL scan"
    if flagsets <= {"S"}:
        return "SYN scan"
    if flagsets <= {"F"}:
        return "FIN scan"
    if flagsets <= {"FPU"}:
        return "XMAS scan"
    return "Connect/mixed scan"


def _pattern(n_ports, n_hosts, threshold):
    if n_hosts >= threshold and n_ports < threshold:
        return "Horizontal sweep"
    if n_ports >= threshold and n_hosts == 1:
        return "Vertical scan"
    return "Block scan"


def _severity(n, threshold, bump):
    if n >= threshold * 5:
        idx = 3
    elif n >= threshold * 2.5:
        idx = 2
    else:
        idx = 1
    if bump and idx < 3:
        idx += 1
    return SEVERITY_ORDER[idx]


def _fmt(t):
    return t.strftime("%Y-%m-%d %H:%M:%S")


def _build_alert(src, best, threshold):
    evs = best["events"]
    ports = sorted(best["ports"])
    hosts = sorted(best["hosts"])
    sensitive = [f"{p}/{SENSITIVE_PORTS[p]}" for p in ports if p in SENSITIVE_PORTS]
    open_ports = sorted({e["dport"] for e in evs if e["action"] in ACCEPT_ACTIONS})
    n = max(len(ports), len(hosts))
    technique = _technique(evs)
    risky_sweep = len(hosts) >= threshold and any(p in RISKY_PORTS for p in ports)
    bump = len(sensitive) >= 3 or technique in EVASIVE or risky_sweep
    times = [e["time"] for e in evs]
    return Alert(
        severity=_severity(n, threshold, bump),
        src_ip=src,
        scan_type=f"{_pattern(len(ports), len(hosts), threshold)} ({technique})",
        unique_ports=len(ports),
        unique_hosts=len(hosts),
        packets=len(evs),
        first_seen=_fmt(min(times)),
        last_seen=_fmt(max(times)),
        targets=", ".join(hosts[:5]) + (" ..." if len(hosts) > 5 else ""),
        open_ports=", ".join(map(str, open_ports)) or "none",
        sensitive_ports=", ".join(sensitive) or "none",
    )


def detect(events, threshold=10, window_sec=10):
    """Alert when one source touches >= threshold distinct ports (or hosts)
    inside a sliding window of window_sec seconds."""
    by_src = defaultdict(list)
    for e in events:
        by_src[e["src"]].append(e)

    alerts = []
    for src, evs in by_src.items():
        evs.sort(key=lambda x: x["time"])
        win, best = deque(), None
        for e in evs:
            win.append(e)
            while (e["time"] - win[0]["time"]).total_seconds() > window_sec:
                win.popleft()
            ports = {x["dport"] for x in win}
            hosts = {x["dst"] for x in win}
            if len(ports) >= threshold or len(hosts) >= threshold:
                score = len(ports) + len(hosts)
                if best is None or score > best["score"]:
                    best = {"score": score, "events": list(win),
                            "ports": ports, "hosts": hosts}
        if best:
            alerts.append(_build_alert(src, best, threshold))

    alerts.sort(key=lambda a: (-SEVERITY_ORDER.index(a.severity), -a.unique_ports))
    return alerts