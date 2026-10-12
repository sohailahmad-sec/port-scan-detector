"""Firewall log parser.

Expected line format (iptables / UFW style, simplified):
2026-10-11 22:18:23 DROP SRC=45.1.2.3 DST=192.168.1.10 PROTO=TCP SPT=44321 DPT=22 FLAGS=S
"""
import re
from datetime import datetime

LINE_RE = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+"
    r"(?P<action>[A-Za-z]+)\s+"
    r"SRC=(?P<src>\S+)\s+DST=(?P<dst>\S+)\s+"
    r"PROTO=(?P<proto>[A-Za-z]+)\s+"
    r"(?:SPT=(?P<spt>\d+)\s+)?"
    r"DPT=(?P<dpt>\d+)"
    r"(?:\s+FLAGS=(?P<flags>\S*))?"
)


def parse_line(line):
    m = LINE_RE.search(line)
    if not m:
        return None
    flags = (m.group("flags") or "").upper()
    if flags == "NONE":
        flags = ""
    flags = "".join(sorted(flags))  # normalise: "PFU" -> "FPU"
    return {
        "time": datetime.strptime(m.group("ts"), "%Y-%m-%d %H:%M:%S"),
        "action": m.group("action").upper(),
        "src": m.group("src"),
        "dst": m.group("dst"),
        "proto": m.group("proto").upper(),
        "sport": int(m.group("spt")) if m.group("spt") else 0,
        "dport": int(m.group("dpt")),
        "flags": flags,
    }


def parse_log(path):
    """Returns (events, bad_line_count)."""
    events, bad = [], 0
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            ev = parse_line(line)
            if ev:
                events.append(ev)
            else:
                bad += 1
    return events, bad