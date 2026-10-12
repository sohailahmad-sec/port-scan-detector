"""Creates a realistic fake firewall log for testing."""
import os
import random
from datetime import datetime, timedelta


def generate_sample_log(path, seed=None):
    rnd = random.Random(seed)
    start = datetime.now().replace(microsecond=0) - timedelta(minutes=5)
    server = "192.168.1.10"
    rows = []

    def add(t, action, src, dst, proto, dpt, flags):
        spt = rnd.randint(30000, 65000)
        rows.append((t, f"{t:%Y-%m-%d %H:%M:%S} {action} SRC={src} DST={dst} "
                        f"PROTO={proto} SPT={spt} DPT={dpt} FLAGS={flags}"))

    # 1) Normal users browsing (should NOT alert)
    for ip in ["192.168.1.50", "192.168.1.51", "203.0.113.77"]:
        for _ in range(12):
            t = start + timedelta(seconds=rnd.randint(0, 280))
            add(t, "ACCEPT", ip, server, "TCP", rnd.choice([80, 443]), "S")

    # 2) Vertical SYN scan on one host (many ports, very fast)
    scanner = "45.155.205.12"
    ports = rnd.sample(range(1, 1025), 45) + [22, 80, 443, 3389, 445]
    t0 = start + timedelta(seconds=60)
    for i, p in enumerate(ports):
        add(t0 + timedelta(milliseconds=i * 80),
            "ACCEPT" if p in (22, 80) else "DROP", scanner, server, "TCP", p, "S")

    # 3) Horizontal sweep: same port (SMB 445) across many hosts
    sweeper = "185.220.101.9"
    for i in range(1, 21):
        add(start + timedelta(seconds=150 + i // 2), "DROP", sweeper,
            f"192.168.1.{i}", "TCP", 445, "S")

    # 4) XMAS scan (FIN+PSH+URG flags)
    xmas = "91.240.118.5"
    for i, p in enumerate(rnd.sample(range(1, 1025), 15)):
        add(start + timedelta(seconds=200 + i // 5), "DROP", xmas, server, "TCP", p, "FPU")

    # 5) Low-and-slow visitor, only 4 ports over minutes (should NOT alert)
    slow = "198.51.100.23"
    for i, p in enumerate([22, 80, 443, 8080]):
        add(start + timedelta(seconds=40 + i * 70), "DROP", slow, server, "TCP", p, "S")

    rows.sort(key=lambda r: r[0])
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(line for _, line in rows) + "\n")
    return path