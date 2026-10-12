"""Port Scan Detector - Security Operations Lab (Tkinter dashboard)."""
import os
import csv
import json
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from collections import Counter

import matplotlib
matplotlib.use("TkAgg")
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

from log_parser import parse_log
from detector import detect, RESPONSE, SEVERITY_ORDER
from sample_generator import generate_sample_log

BASE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE, "data")
OUT_DIR = os.path.join(BASE, "output")
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(OUT_DIR, exist_ok=True)

BG, PANEL, PANEL2 = "#0b1220", "#111a2b", "#16233a"
FG, MUTED, ACCENT = "#e6edf3", "#8b9bb4", "#22d3ee"
SEV_COLOR = {"LOW": "#4ade80", "MEDIUM": "#facc15", "HIGH": "#fb923c",
             "CRITICAL": "#ff4d4f", "SAFE": "#4ade80"}


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Port Scan Detector - Security Operations Lab")
        self.geometry("1280x860")
        self.minsize(1100, 760)
        self.configure(bg=BG)
        self.events, self.alerts, self.log_path = [], [], None
        self.threshold = tk.IntVar(value=10)
        self.window = tk.IntVar(value=10)
        self._style()
        self._header()
        self._rule_bar()
        self._cards()
        # bottom widgets are packed BEFORE the middle section so they never get cut off
        self.status = tk.Label(self, text="Load a log or generate a sample log.",
                               bg=BG, fg=MUTED, anchor="w", font=("Segoe UI", 9))
        self.status.pack(side="bottom", fill="x", padx=16, pady=(0, 6))
        self._charts()
        self._middle()

    # ---------- UI building ----------
    def _style(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure("Treeview", background=PANEL, fieldbackground=PANEL,
                    foreground=FG, rowheight=26, borderwidth=0, bordercolor=PANEL,
                    lightcolor=PANEL, darkcolor=PANEL, font=("Segoe UI", 10))
        s.configure("Treeview.Heading", background=PANEL2, foreground=ACCENT,
                    font=("Segoe UI", 10, "bold"), borderwidth=0)
        s.map("Treeview", background=[("selected", "#1e3a5f")])

    def _btn(self, parent, text, cmd, primary=False):
        return tk.Button(parent, text=text, command=cmd, relief="flat", cursor="hand2",
                         bg=ACCENT if primary else PANEL2,
                         fg="#06121f" if primary else FG,
                         activebackground="#67e8f9" if primary else "#1e3354",
                         font=("Segoe UI", 10, "bold"), padx=14, pady=8)

    def _header(self):
        h = tk.Frame(self, bg=BG)
        h.pack(fill="x", padx=16, pady=(14, 6))
        left = tk.Frame(h, bg=BG)
        left.pack(side="left")
        tk.Label(left, text="PORT SCAN DETECTOR", bg=BG, fg=FG,
                 font=("Segoe UI", 20, "bold")).pack(anchor="w")
        tk.Label(left, text="Security Operations Lab  |  Firewall Log Analysis  |  "
                            "MITRE ATT&CK T1046 - Network Service Discovery",
                 bg=BG, fg=MUTED, font=("Segoe UI", 9)).pack(anchor="w")
        right = tk.Frame(h, bg=BG)
        right.pack(side="right")
        for text, cmd, prim in [("Open Log File", self.open_log, False),
                                ("Generate Sample Log", self.make_sample, False),
                                ("Export CSV", self.export_csv, False),
                                ("Export JSON (SIEM)", self.export_json, False),
                                ("RUN DETECTION", self.run_detection, True)]:
            self._btn(right, text, cmd, prim).pack(side="left", padx=3)

    def _stepper(self, parent, var, lo, hi):
        f = tk.Frame(parent, bg=PANEL2)
        def bump(d):
            var.set(max(lo, min(hi, var.get() + d)))
        tk.Button(f, text="-", width=2, relief="flat", bg=PANEL2, fg=ACCENT,
                  command=lambda: bump(-1)).pack(side="left")
        tk.Label(f, textvariable=var, width=4, bg=PANEL2, fg=FG,
                 font=("Segoe UI", 11, "bold")).pack(side="left")
        tk.Button(f, text="+", width=2, relief="flat", bg=PANEL2, fg=ACCENT,
                  command=lambda: bump(1)).pack(side="left")
        return f

    def _rule_bar(self):
        bar = tk.Frame(self, bg=PANEL)
        bar.pack(fill="x", padx=16, pady=6)
        tk.Label(bar, text="DETECTION RULE", bg=PANEL, fg=MUTED,
                 font=("Segoe UI", 9, "bold")).pack(side="left", padx=(12, 10), pady=10)
        tk.Label(bar, text="Alert when one IP touches at least", bg=PANEL,
                 fg=FG).pack(side="left")
        self._stepper(bar, self.threshold, 2, 500).pack(side="left", padx=6)
        tk.Label(bar, text="distinct ports/hosts within", bg=PANEL, fg=FG).pack(side="left")
        self._stepper(bar, self.window, 1, 600).pack(side="left", padx=6)
        tk.Label(bar, text="second(s)", bg=PANEL, fg=FG).pack(side="left")
        self.src_lbl = tk.Label(bar, text="Log source: -", bg=PANEL, fg=MUTED,
                                font=("Consolas", 9))
        self.src_lbl.pack(side="right", padx=12)

    def _cards(self):
        row = tk.Frame(self, bg=BG)
        row.pack(fill="x", padx=12, pady=4)
        self.cards = {}
        spec = [("events", "TOTAL EVENTS", ACCENT), ("sources", "UNIQUE SOURCES", "#a78bfa"),
                ("alerts", "ALERTS", "#facc15"), ("severe", "CRITICAL / HIGH", "#ff4d4f"),
                ("threat", "THREAT LEVEL", "#4ade80")]
        for key, title, color in spec:
            box = tk.Frame(row, bg=PANEL)
            box.pack(side="left", fill="x", expand=True, padx=4)
            tk.Frame(box, bg=color, height=3).pack(fill="x")
            tk.Label(box, text=title, bg=PANEL, fg=MUTED,
                     font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=12, pady=(8, 0))
            lbl = tk.Label(box, text="0", bg=PANEL, fg=color, font=("Segoe UI", 24, "bold"))
            lbl.pack(anchor="w", padx=12, pady=(0, 8))
            self.cards[key] = lbl

    def _middle(self):
        mid = tk.Frame(self, bg=BG)
        mid.pack(fill="both", expand=True, padx=16, pady=6)
        mid.columnconfigure(0, weight=5)
        mid.columnconfigure(1, weight=4)
        mid.rowconfigure(0, weight=1)

        left = tk.Frame(mid, bg=PANEL)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        cols = ("sev", "ip", "type", "ports", "hosts", "pkts", "first", "last")
        heads = ("Severity", "Source IP", "Scan Type", "Ports", "Hosts", "Packets",
                 "First", "Last")
        widths = (75, 110, 190, 50, 50, 65, 70, 70)
        self.tree = ttk.Treeview(left, columns=cols, show="headings", height=8)
        for c, h, w in zip(cols, heads, widths):
            self.tree.heading(c, text=h)
            self.tree.column(c, width=w, minwidth=w, anchor="w", stretch=(c == "type"))
        for sev, color in SEV_COLOR.items():
            self.tree.tag_configure(sev, foreground=color)
        sb = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self.show_detail)

        right = tk.Frame(mid, bg=PANEL)
        right.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        tk.Label(right, text="ALERT DETAILS & RECOMMENDED RESPONSE", bg=PANEL, fg=MUTED,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=12, pady=8)
        box = tk.Frame(right, bg=PANEL)
        box.pack(fill="both", expand=True, padx=12, pady=(0, 10))
        dsb = ttk.Scrollbar(box, orient="vertical")
        self.detail = tk.Text(box, bg=PANEL, fg=FG, font=("Consolas", 10), relief="flat",
                              wrap="word", height=8, state="disabled", yscrollcommand=dsb.set)
        dsb.config(command=self.detail.yview)
        dsb.pack(side="right", fill="y")
        self.detail.pack(side="left", fill="both", expand=True)
        self.detail.tag_configure("key", foreground=MUTED)
        self.detail.tag_configure("rec", foreground=ACCENT)
        for sev, color in SEV_COLOR.items():
            self.detail.tag_configure(sev, foreground=color, font=("Consolas", 11, "bold"))

    def _charts(self):
        frame = tk.Frame(self, bg=PANEL)
        frame.pack(side="bottom", fill="x", padx=16, pady=6)
        self.fig = Figure(figsize=(10, 2.3), dpi=100, facecolor=PANEL)
        self.ax1 = self.fig.add_subplot(121)
        self.ax2 = self.fig.add_subplot(122)
        self.canvas = FigureCanvasTkAgg(self.fig, master=frame)
        self.canvas.get_tk_widget().pack(fill="x")
        self._draw_charts()

    # ---------- actions ----------
    def open_log(self):
        path = filedialog.askopenfilename(initialdir=DATA_DIR,
                                          filetypes=[("Log files", "*.log *.txt"), ("All", "*.*")])
        if path:
            self.load(path)

    def make_sample(self):
        self.load(generate_sample_log(os.path.join(DATA_DIR, "firewall_sample.log")))

    def load(self, path):
        try:
            self.events, bad = parse_log(path)
        except OSError as e:
            messagebox.showerror("Error", str(e))
            return
        self.log_path = path
        self.src_lbl.config(text=f"Log source: {path}")
        self.status.config(text=f"Loaded {len(self.events)} events ({bad} unparsable lines skipped).")
        self.run_detection()

    def run_detection(self):
        if not self.events:
            messagebox.showinfo("No data", "Open a log file or generate a sample log first.")
            return
        self.alerts = detect(self.events, self.threshold.get(), self.window.get())
        self.refresh()

    def refresh(self):
        self.tree.delete(*self.tree.get_children())
        for i, a in enumerate(self.alerts):
            self.tree.insert("", "end", iid=str(i), tags=(a.severity,),
                             values=(a.severity, a.src_ip, a.scan_type, a.unique_ports,
                                     a.unique_hosts, a.packets, a.first_seen[11:], a.last_seen[11:]))
        top = self.alerts[0].severity if self.alerts else "SAFE"
        severe = sum(a.severity in ("HIGH", "CRITICAL") for a in self.alerts)
        self.cards["events"].config(text=str(len(self.events)))
        self.cards["sources"].config(text=str(len({e["src"] for e in self.events})))
        self.cards["alerts"].config(text=str(len(self.alerts)))
        self.cards["severe"].config(text=str(severe))
        self.cards["threat"].config(text=top, fg=SEV_COLOR[top])
        self.status.config(text=f"Analyzed {len(self.events)} events | {len(self.alerts)} alert(s) | "
                                f"Rule: >= {self.threshold.get()} distinct ports/hosts "
                                f"within {self.window.get()} sec")
        self._set_detail("")
        self._draw_charts()
        if self.alerts:
            self.tree.selection_set("0")

    def show_detail(self, _=None):
        sel = self.tree.selection()
        if not sel:
            return
        a = self.alerts[int(sel[0])]
        self.detail.config(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("end", f"[{a.severity}] Port scan detected\n\n", a.severity)
        rows = [("Source IP", a.src_ip), ("Scan type", a.scan_type),
                ("Distinct ports", a.unique_ports), ("Distinct hosts", a.unique_hosts),
                ("Packets", a.packets), ("First seen", a.first_seen),
                ("Last seen", a.last_seen), ("Targets", a.targets),
                ("Sensitive ports", a.sensitive_ports),
                ("OPEN (accepted)", a.open_ports), ("MITRE ATT&CK", a.mitre)]
        for k, v in rows:
            self.detail.insert("end", f"{k:<16}", "key")
            self.detail.insert("end", f"{v}\n")
        self.detail.insert("end", "\nRecommended response\n", "rec")
        for step in RESPONSE.get(a.severity, RESPONSE["MEDIUM"]):
            self.detail.insert("end", f" - {step}\n")
        self.detail.config(state="disabled")

    def _set_detail(self, text):
        self.detail.config(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("end", text)
        self.detail.config(state="disabled")

    def _draw_charts(self):
        for ax in (self.ax1, self.ax2):
            ax.clear()
            ax.set_facecolor(PANEL)
            ax.tick_params(colors=MUTED, labelsize=8)
            for sp in ax.spines.values():
                sp.set_color("#243247")
        self.ax1.set_title("Top Scanner IPs (distinct ports / hosts)", color=FG, fontsize=10, loc="left")
        self.ax2.set_title("Most Targeted Ports (scanners only)", color=FG, fontsize=10, loc="left")
        if self.alerts:
            top = self.alerts[:6]
            self.ax1.barh([a.src_ip for a in top][::-1], [max(a.unique_ports, a.unique_hosts) for a in top][::-1],
                          color=[SEV_COLOR[a.severity] for a in top][::-1])
            ips = {a.src_ip for a in self.alerts}
            c = Counter(e["dport"] for e in self.events if e["src"] in ips).most_common(8)
            self.ax2.bar([str(p) for p, _ in c], [n for _, n in c], color=ACCENT)
        else:
            for ax in (self.ax1, self.ax2):
                ax.text(0.5, 0.5, "No scanners detected", color=MUTED, ha="center",
                        va="center", transform=ax.transAxes)
        self.fig.tight_layout()
        self.canvas.draw()

    # ---------- exports ----------
    def export_csv(self):
        if not self.alerts:
            messagebox.showinfo("Nothing to export", "Run detection first.")
            return
        path = filedialog.asksaveasfilename(initialdir=OUT_DIR, defaultextension=".csv",
                                            initialfile="port_scan_alerts.csv")
        if path:
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=list(self.alerts[0].to_dict().keys()))
                w.writeheader()
                for a in self.alerts:
                    w.writerow(a.to_dict())
            self.status.config(text=f"Exported CSV: {path}")

    def export_json(self):
        """One JSON object per line - ready to ingest into Splunk / ELK / Wazuh."""
        if not self.alerts:
            messagebox.showinfo("Nothing to export", "Run detection first.")
            return
        path = filedialog.asksaveasfilename(initialdir=OUT_DIR, defaultextension=".json",
                                            initialfile="port_scan_alerts.json")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                for a in self.alerts:
                    f.write(json.dumps({"sourcetype": "port_scan_alert", **a.to_dict()}) + "\n")
            self.status.config(text=f"Exported JSON: {path}")


if __name__ == "__main__":
    App().mainloop()