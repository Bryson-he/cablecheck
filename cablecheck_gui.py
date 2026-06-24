"""
cablecheck_gui.py — Dual-NIC loopback cable tester (Tkinter GUI v3)
Run as Administrator. Requires: pip install scapy psutil
"""

import csv, ctypes, os, sys, time, uuid, threading, winsound
import tkinter as tk
from tkinter import ttk
from datetime import datetime
from pathlib import Path

try:
    import psutil
    from scapy.all import Ether, IP, UDP, Raw, sendp, sniff
except ImportError:
    import tkinter.messagebox as mb
    r = tk.Tk(); r.withdraw()
    mb.showerror("Missing dependencies", "Run:  pip install scapy psutil")
    sys.exit(1)

# ── Config ──────────────────────────────────────────────────────────────────
PACKET_COUNT    = 50
PACKET_TIMEOUT  = 3.0
TEST_PORT       = 59876
MAGIC           = b"CABLECHECK"
DEFAULT_A       = "Ethernet"
DEFAULT_B       = "Ethernet 4"
LOG_DIR         = Path("logs")
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE        = LOG_DIR / f"cablecheck_{datetime.now().strftime('%Y%m%d')}.csv"
CSV_HEADERS     = [
    "timestamp","cable_id","adapter_a","adapter_b",
    "link_speed_a_mbps","link_speed_b_mbps",
    "packets_sent","packets_received","packet_loss_pct",
    "rtt_avg_ms","rtt_min_ms","rtt_max_ms",
    "errors_in_a","errors_out_a","errors_in_b","errors_out_b",
    "result","fault_reason"
]

# ── Palette ──────────────────────────────────────────────────────────────────
BG      = "#0d0f18"
BG2     = "#13161f"
BG3     = "#1c1f2e"
BG4     = "#232740"
BORDER  = "#2a2d45"
TEXT    = "#e2e4f0"
MUTED   = "#565a7a"
DIM     = "#2e3150"
PASS_C  = "#22c55e"
WARN_C  = "#f59e0b"
FAIL_C  = "#ef4444"
ACCENT  = "#6366f1"
ACCENT2 = "#818cf8"
PKT_OK  = "#22c55e"
PKT_MISS= "#ef4444"
PKT_PEND= "#1c1f2e"

# ── NIC helpers ──────────────────────────────────────────────────────────────
def get_adapters():
    out = []
    for name, stat in psutil.net_if_stats().items():
        if stat.isup and stat.speed > 0:
            out.append({"name": name, "speed": stat.speed})
    return out

def get_all_adapter_names():
    return list(psutil.net_if_stats().keys())

def is_link_up(name):
    s = psutil.net_if_stats().get(name)
    return s is not None and s.isup and s.speed > 0

def get_nic_counters(name):
    c = psutil.net_io_counters(pernic=True).get(name)
    if not c: return {"errin":0,"errout":0,"dropin":0,"dropout":0}
    return {"errin":c.errin,"errout":c.errout,"dropin":c.dropin,"dropout":c.dropout}

def counter_delta(a, b): return {k: b[k]-a[k] for k in a}
def get_link_speed(name):
    s = psutil.net_if_stats().get(name)
    return s.speed if s else 0

# ── Core test ────────────────────────────────────────────────────────────────
def run_loopback_test(adapter_a, adapter_b, cable_id, pkt_cb=None, log_cb=None):
    session_id = uuid.uuid4().bytes[:4]
    received   = {}
    lock       = threading.Lock()
    rtts       = []
    send_times = {}
    before_a   = get_nic_counters(adapter_a)
    before_b   = get_nic_counters(adapter_b)

    def build_pkt(seq):
        payload = MAGIC + session_id + seq.to_bytes(2,"big")
        return (Ether(dst="ff:ff:ff:ff:ff:ff") /
                IP(dst="192.168.99.1") /
                UDP(dport=TEST_PORT, sport=TEST_PORT) /
                Raw(load=payload))

    def handler(pkt):
        try:
            raw = bytes(pkt[Raw].load)
            if not raw.startswith(MAGIC): return
            if raw[len(MAGIC):len(MAGIC)+4] != session_id: return
            seq  = int.from_bytes(raw[len(MAGIC)+4:len(MAGIC)+6],"big")
            rx_t = time.perf_counter()
            with lock:
                if seq in send_times and seq not in received:
                    rtt = (rx_t - send_times[seq]) * 1000
                    received[seq] = rtt
                    rtts.append(rtt)
                    if pkt_cb: pkt_cb(seq, "ok", round(rtt,1))
        except Exception:
            pass

    stop_ev = threading.Event()
    def sniffer():
        sniff(iface=adapter_b, filter=f"udp port {TEST_PORT}",
              prn=handler, store=False,
              stop_filter=lambda _: stop_ev.is_set(),
              timeout=PACKET_TIMEOUT+2)

    t = threading.Thread(target=sniffer, daemon=True)
    t.start()
    time.sleep(0.3)
    if log_cb: log_cb(f"Sniffer ready on {adapter_b}")

    # warmup burst — 10 throwaway packets to flush ARP/switch table/NIC buffer spikes
    if log_cb: log_cb("Warming up path — sending 10 throwaway packets...")
    warmup_id = uuid.uuid4().bytes[:4]
    for seq in range(10):
        payload = MAGIC + warmup_id + seq.to_bytes(2,"big")
        warmup_pkt = (Ether(dst="ff:ff:ff:ff:ff:ff") /
                      IP(dst="192.168.99.1") /
                      UDP(dport=TEST_PORT, sport=TEST_PORT) /
                      Raw(load=payload))
        sendp(warmup_pkt, iface=adapter_a, verbose=False)
        time.sleep(0.02)
    time.sleep(0.5)
    if log_cb: log_cb(f"Warmup done — sending {PACKET_COUNT} test packets via {adapter_a}...")

    for seq in range(PACKET_COUNT):
        pkt = build_pkt(seq)
        send_times[seq] = time.perf_counter()
        sendp(pkt, iface=adapter_a, verbose=False)
        time.sleep(0.02)

    if log_cb: log_cb("All packets sent — waiting for stragglers...")
    time.sleep(PACKET_TIMEOUT)
    stop_ev.set()
    t.join(timeout=3)

    for seq in range(PACKET_COUNT):
        if seq not in received:
            if pkt_cb: pkt_cb(seq, "miss", None)

    after_a  = get_nic_counters(adapter_a)
    after_b  = get_nic_counters(adapter_b)
    da       = counter_delta(before_a, after_a)
    db       = counter_delta(before_b, after_b)
    rx_count = len(received)
    loss_pct = round((PACKET_COUNT - rx_count) / PACKET_COUNT * 100, 1)
    rtt_avg  = round(sum(rtts)/len(rtts),2) if rtts else None
    rtt_min  = round(min(rtts),2) if rtts else None
    rtt_max  = round(max(rtts),2) if rtts else None
    speed_a  = get_link_speed(adapter_a)
    speed_b  = get_link_speed(adapter_b)

    fault = None
    if rx_count == 0:
        result, fault = "FAIL", "No packets received — open circuit or no link"
    elif loss_pct > 5:
        result, fault = "FAIL", f"{loss_pct}% packet loss — bad crimp or marginal cable"
    elif da["errin"]+da["errout"]+db["errin"]+db["errout"] > 5:
        result, fault = "WARN", "Elevated NIC errors — possible split pair or poor termination"
    elif rtt_avg and rtt_avg > 10:
        result, fault = "WARN", f"High avg RTT {rtt_avg}ms — cable may be marginal"
    elif speed_a < 1000 or speed_b < 1000:
        result, fault = "WARN", f"Link below Gigabit (A:{speed_a} B:{speed_b} Mbps) — check pairs 4,5,7,8"
    else:
        result = "PASS"

    if log_cb:
        log_cb(f"Received {rx_count}/{PACKET_COUNT}  loss={loss_pct}%  " +
               (f"rtt avg={rtt_avg}ms  min={rtt_min}ms  max={rtt_max}ms" if rtt_avg else "rtt=n/a"))
        log_cb(f"NIC errors  A in:{da['errin']} out:{da['errout']}  "
               f"B in:{db['errin']} out:{db['errout']}")
        log_cb(f"Link speed  A:{speed_a}Mbps  B:{speed_b}Mbps")
        log_cb(f"Result: {result}" + (f" — {fault}" if fault else ""))

    return {
        "timestamp":         datetime.now().isoformat(timespec="seconds"),
        "cable_id":          cable_id,
        "adapter_a":         adapter_a, "adapter_b": adapter_b,
        "link_speed_a_mbps": speed_a,  "link_speed_b_mbps": speed_b,
        "packets_sent":      PACKET_COUNT, "packets_received": rx_count,
        "packet_loss_pct":   loss_pct,
        "rtt_avg_ms":        rtt_avg, "rtt_min_ms": rtt_min, "rtt_max_ms": rtt_max,
        "errors_in_a":       da["errin"],  "errors_out_a": da["errout"],
        "errors_in_b":       db["errin"],  "errors_out_b": db["errout"],
        "result":            result, "fault_reason": fault or "",
    }

def init_csv():
    if not LOG_FILE.exists():
        with open(LOG_FILE,"w",newline="") as f:
            csv.DictWriter(f, fieldnames=CSV_HEADERS).writeheader()

def log_result(r):
    with open(LOG_FILE,"a",newline="") as f:
        csv.DictWriter(f, fieldnames=CSV_HEADERS).writerow(r)

def beep(result):
    try:
        if result == "PASS":
            winsound.Beep(1000, 120)
        elif result == "WARN":
            winsound.Beep(700, 200); time.sleep(0.05); winsound.Beep(700, 200)
        else:
            winsound.Beep(400, 400); time.sleep(0.05); winsound.Beep(300, 400)
    except Exception:
        pass

# ── App ───────────────────────────────────────────────────────────────────────
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("cablecheck")
        self.geometry("980x800")
        self.minsize(860, 700)
        self.configure(bg=BG)
        self.adapters    = get_adapters()
        self.cable_num   = 1
        self.testing     = False
        self.auto_test   = tk.BooleanVar(value=False)
        self.sound_on    = tk.BooleanVar(value=True)
        self.prefix_var  = tk.StringVar(value="CABLE")
        self._pkt_state  = ["idle"] * PACKET_COUNT
        # session stats
        self._sess_total = 0
        self._sess_pass  = 0
        self._sess_warn  = 0
        self._sess_fail  = 0
        self._sess_rtts  = []
        # consecutive fail tracking
        self._consec_fail   = 0
        self._auto_watching = False   # True when waiting for unplug→replug cycle
        self._build()
        init_csv()
        self.bind("<Return>", lambda e: self._start_test())
        self._poll_link()

    # ── Top stats bar ────────────────────────────────────────────────────────
    def _build(self):
        # ── session stats strip ──────────────────────────────────────────────
        stats_bar = tk.Frame(self, bg=BG2)
        stats_bar.pack(fill="x")

        inner_stats = tk.Frame(stats_bar, bg=BG2)
        inner_stats.pack(fill="x", padx=28, pady=10)

        tk.Label(inner_stats, text="cablecheck", font=("Segoe UI",16,"bold"),
                 bg=BG2, fg=ACCENT2).pack(side="left")
        tk.Label(inner_stats, text="  dual-NIC loopback tester",
                 font=("Segoe UI",10), bg=BG2, fg=MUTED).pack(side="left", pady=2)

        # session counters on the right
        sess_right = tk.Frame(inner_stats, bg=BG2)
        sess_right.pack(side="right")

        self._sess_labels = {}
        for key, label, col in [
            ("total","TESTED", TEXT),
            ("pass", "PASS",   PASS_C),
            ("warn", "WARN",   WARN_C),
            ("fail", "FAIL",   FAIL_C),
            ("rate", "PASS RATE", ACCENT2),
        ]:
            blk = tk.Frame(sess_right, bg=BG2)
            blk.pack(side="left", padx=14)
            v = tk.StringVar(value="0" if key != "rate" else "—")
            self._sess_labels[key] = v
            tk.Label(blk, textvariable=v, font=("Segoe UI",18,"bold"),
                     bg=BG2, fg=col).pack()
            tk.Label(blk, text=label, font=("Segoe UI",7),
                     bg=BG2, fg=MUTED).pack()

        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")

        # ── main body ────────────────────────────────────────────────────────
        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True)
        body.columnconfigure(0, weight=3)
        body.columnconfigure(1, weight=2)
        body.rowconfigure(0, weight=1)

        left  = tk.Frame(body, bg=BG)
        left.grid(row=0, column=0, sticky="nsew", padx=(24,10), pady=18)
        right = tk.Frame(body, bg=BG)
        right.grid(row=0, column=1, sticky="nsew", padx=(10,24), pady=18)

        self._build_left(left)
        self._build_right(right)

    def _sec(self, parent, text):
        tk.Label(parent, text=text.upper(), font=("Segoe UI",8,"bold"),
                 bg=BG, fg=DIM).pack(anchor="w", pady=(0,5))

    # ── Left panel ───────────────────────────────────────────────────────────
    def _build_left(self, p):

        # adapters card
        self._sec(p, "adapters")
        af = tk.Frame(p, bg=BG3, highlightthickness=1, highlightbackground=BORDER)
        af.pack(fill="x", pady=(0,14))

        self._link_dots = {}
        for label, attr, default in [
            ("End A  —  built-in ethernet", "combo_a", DEFAULT_A),
            ("End B  —  USB ethernet",      "combo_b", DEFAULT_B),
        ]:
            row = tk.Frame(af, bg=BG3)
            row.pack(fill="x", padx=14, pady=10)

            # link state dot
            dot = tk.Canvas(row, width=10, height=10, bg=BG3,
                            highlightthickness=0)
            dot.pack(side="left", padx=(0,8))
            dot.create_oval(1,1,9,9, fill=MUTED, outline="", tags="dot")
            self._link_dots[attr] = dot

            tk.Label(row, text=label, font=("Segoe UI",10), bg=BG3,
                     fg=MUTED, width=26, anchor="w").pack(side="left")

            cb = ttk.Combobox(row, state="readonly", font=("Segoe UI",10), width=26)
            cb.pack(side="left", ipady=4)
            setattr(self, attr, cb)
            setattr(self, f"_{attr}_default", default)

            tk.Frame(af, bg=BORDER, height=1).pack(fill="x")

        # populate combos
        names = [f"{a['name']}  ({a['speed']} Mbps)" for a in self.adapters]
        for attr in ("combo_a","combo_b"):
            cb = getattr(self, attr)
            cb["values"] = names
            default = getattr(self, f"_{attr}_default")
            matched = next((i for i,a in enumerate(self.adapters)
                           if a["name"] == default), None)
            if matched is not None:
                cb.current(matched)
            elif names:
                cb.current(0 if attr=="combo_a" else min(1,len(names)-1))

        # options row
        opts = tk.Frame(p, bg=BG)
        opts.pack(fill="x", pady=(0,14))

        # prefix
        tk.Label(opts, text="Prefix", font=("Segoe UI",10),
                 bg=BG, fg=MUTED).pack(side="left", padx=(0,6))
        tk.Entry(opts, textvariable=self.prefix_var,
                 font=("Segoe UI",10), bg=BG3, fg=TEXT,
                 insertbackground=TEXT, relief="flat", bd=0, width=8,
                 highlightthickness=1, highlightbackground=BORDER,
                 highlightcolor=ACCENT).pack(side="left", ipady=5, padx=(0,14))

        # cable ID
        tk.Label(opts, text="Cable ID", font=("Segoe UI",10),
                 bg=BG, fg=MUTED).pack(side="left", padx=(0,6))
        self.id_var = tk.StringVar(value="CABLE-001")
        tk.Entry(opts, textvariable=self.id_var,
                 font=("Segoe UI",11), bg=BG3, fg=TEXT,
                 insertbackground=TEXT, relief="flat", bd=0, width=10,
                 highlightthickness=1, highlightbackground=BORDER,
                 highlightcolor=ACCENT).pack(side="left", ipady=5, padx=(0,14))

        self.prefix_var.trace_add("write", lambda *_: self._update_cable_id())

        # toggles
        self.auto_test.trace_add("write", lambda *_: self._on_auto_toggle())
        for var, label in [(self.sound_on,"Sound"),(self.auto_test,"Auto-test")]:
            tk.Checkbutton(opts, text=label, variable=var,
                          font=("Segoe UI",10), bg=BG, fg=MUTED,
                          selectcolor=BG3, activebackground=BG,
                          activeforeground=TEXT).pack(side="left", padx=6)

        # run button
        self.test_btn = tk.Button(opts, text="Run Test  →",
                                   font=("Segoe UI",11,"bold"),
                                   bg=ACCENT, fg="white",
                                   activebackground=ACCENT2, activeforeground="white",
                                   relief="flat", bd=0, cursor="hand2",
                                   padx=18, pady=7, command=self._start_test)
        self.test_btn.pack(side="right")

        # result banner
        self._sec(p, "result")
        self.banner = tk.Frame(p, bg=BG3, highlightthickness=2,
                                highlightbackground=BORDER)
        self.banner.pack(fill="x", pady=(0,14))

        self.result_title = tk.Label(self.banner, text="—",
                                      font=("Segoe UI",36,"bold"),
                                      bg=BG3, fg=MUTED)
        self.result_title.pack(pady=(18,2))

        self.result_cable = tk.Label(self.banner, text="no test run yet",
                                      font=("Segoe UI",12,"bold"),
                                      bg=BG3, fg=MUTED)
        self.result_cable.pack()

        self.result_fault = tk.Label(self.banner, text="",
                                      font=("Segoe UI",10),
                                      bg=BG3, fg=MUTED, wraplength=380)
        self.result_fault.pack(pady=(4,18))

        # warn strip for consecutive fails
        self.consec_lbl = tk.Label(p, text="", font=("Segoe UI",9),
                                    bg=BG, fg=WARN_C)
        self.consec_lbl.pack(anchor="w", pady=(0,2))

        self.auto_status_lbl = tk.Label(p, text="", font=("Segoe UI",10,"bold"),
                                         bg=BG, fg=ACCENT2)
        self.auto_status_lbl.pack(anchor="w", pady=(0,4))

        # diagnostics
        self._sec(p, "diagnostics")
        sf = tk.Frame(p, bg=BG3, highlightthickness=1, highlightbackground=BORDER)
        sf.pack(fill="x", pady=(0,14))
        self.stat_vars = {}
        drows = [("Link speed","link"),("Packets","packets"),
                 ("RTT","rtt"),("NIC errors","errors"),("Fault","fault")]
        for i,(label,key) in enumerate(drows):
            row = tk.Frame(sf, bg=BG3)
            row.pack(fill="x", padx=14, pady=6)
            tk.Label(row, text=label, font=("Segoe UI",10), bg=BG3,
                     fg=MUTED, width=12, anchor="w").pack(side="left")
            v = tk.StringVar(value="—")
            self.stat_vars[key] = v
            tk.Label(row, textvariable=v, font=("Segoe UI",10),
                     bg=BG3, fg=TEXT, anchor="w").pack(side="left")
            if i < len(drows)-1:
                tk.Frame(sf, bg=BORDER, height=1).pack(fill="x")

        # history
        self._sec(p, "session history")
        hrow = tk.Frame(p, bg=BG)
        hrow.pack(fill="x", pady=(0,5))
        tk.Button(hrow, text="Open CSV", font=("Segoe UI",9),
                  bg=BG3, fg=MUTED, relief="flat", bd=0, cursor="hand2",
                  padx=8, pady=3,
                  command=lambda: os.startfile(LOG_FILE)).pack(side="right")

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("H.Treeview", background=BG3, fieldbackground=BG3,
                         foreground=TEXT, font=("Segoe UI",10), rowheight=24,
                         bordercolor=BORDER)
        style.configure("H.Treeview.Heading", background=BG4, foreground=MUTED,
                         font=("Segoe UI",8,"bold"), relief="flat")
        style.map("H.Treeview", background=[("selected", BG4)])

        tw = tk.Frame(p, bg=BG3, highlightthickness=1, highlightbackground=BORDER)
        tw.pack(fill="both", expand=True)
        cols = ("cable_id","result","loss","rtt","fault")
        self.tree = ttk.Treeview(tw, columns=cols, show="headings",
                                  style="H.Treeview", height=6)
        for col,w,txt,anc in [("cable_id",95,"Cable ID","center"),
                               ("result",65,"Result","center"),
                               ("loss",60,"Loss %","center"),
                               ("rtt",75,"RTT avg","center"),
                               ("fault",240,"Fault","w")]:
            self.tree.heading(col, text=txt)
            self.tree.column(col, width=w, anchor=anc)
        sb = ttk.Scrollbar(tw, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.tree.tag_configure("PASS", foreground=PASS_C)
        self.tree.tag_configure("WARN", foreground=WARN_C)
        self.tree.tag_configure("FAIL", foreground=FAIL_C)

    # ── Right panel ──────────────────────────────────────────────────────────
    def _build_right(self, p):
        self._sec(p, "live packets")
        grid_card = tk.Frame(p, bg=BG3, highlightthickness=1,
                              highlightbackground=BORDER)
        grid_card.pack(fill="x", pady=(0,14))

        legend = tk.Frame(grid_card, bg=BG3)
        legend.pack(fill="x", padx=12, pady=(10,6))
        for col, label in [(PKT_OK,"received"),(PKT_MISS,"missed"),(PKT_PEND,"pending")]:
            dot = tk.Frame(legend, bg=col, width=10, height=10)
            dot.pack(side="left", padx=(0,4))
            dot.pack_propagate(False)
            tk.Label(legend, text=label, font=("Segoe UI",9),
                     bg=BG3, fg=MUTED).pack(side="left", padx=(0,12))

        grid_inner = tk.Frame(grid_card, bg=BG3)
        grid_inner.pack(padx=12, pady=(0,12))
        COLS = 10
        self._pkt_cells = []
        for i in range(PACKET_COUNT):
            cell = tk.Frame(grid_inner, bg=PKT_PEND, width=30, height=30)
            cell.grid(row=i//COLS, column=i%COLS, padx=2, pady=2)
            cell.grid_propagate(False)
            num = tk.Label(cell, text=str(i+1), font=("Segoe UI",8),
                           bg=PKT_PEND, fg=DIM)
            num.place(relx=0.5, rely=0.5, anchor="center")
            self._pkt_cells.append((cell, num))

        # live counters
        self._sec(p, "counters")
        counters_card = tk.Frame(p, bg=BG3, highlightthickness=1,
                                  highlightbackground=BORDER)
        counters_card.pack(fill="x", pady=(0,14))

        metric_row = tk.Frame(counters_card, bg=BG3)
        metric_row.pack(fill="x", padx=4, pady=12)
        self._metric_vars = {}
        for key, label, col in [
            ("sent",    "Sent",       TEXT),
            ("recv",    "Received",   PASS_C),
            ("miss",    "Missed",     FAIL_C),
            ("rtt_live","Avg RTT ms", ACCENT2),
        ]:
            blk = tk.Frame(metric_row, bg=BG3)
            blk.pack(side="left", expand=True)
            v = tk.StringVar(value="0" if key != "rtt_live" else "—")
            self._metric_vars[key] = v
            tk.Label(blk, textvariable=v, font=("Segoe UI",26,"bold"),
                     bg=BG3, fg=col).pack()
            tk.Label(blk, text=label, font=("Segoe UI",9),
                     bg=BG3, fg=MUTED).pack()

        # progress
        style = ttk.Style()
        style.configure("C.Horizontal.TProgressbar",
                         troughcolor=BG4, background=ACCENT,
                         bordercolor=BG4, lightcolor=ACCENT, darkcolor=ACCENT)
        prog_frame = tk.Frame(p, bg=BG)
        prog_frame.pack(fill="x", pady=(0,14))
        self.progress = ttk.Progressbar(prog_frame, style="C.Horizontal.TProgressbar",
                                         maximum=PACKET_COUNT)
        self.progress.pack(fill="x")
        self.prog_lbl = tk.Label(prog_frame, text="", font=("Segoe UI",9),
                                  bg=BG, fg=MUTED)
        self.prog_lbl.pack(anchor="e")

        # live log
        self._sec(p, "live log")
        log_card = tk.Frame(p, bg=BG3, highlightthickness=1,
                             highlightbackground=BORDER)
        log_card.pack(fill="both", expand=True)

        self.log_txt = tk.Text(log_card, bg=BG2, fg=TEXT,
                                font=("Consolas",9), relief="flat",
                                bd=0, state="disabled", wrap="word",
                                padx=10, pady=8,
                                insertbackground=TEXT,
                                selectbackground=BG4)
        self.log_txt.pack(fill="both", expand=True, padx=1, pady=1)
        self.log_txt.tag_configure("ok",   foreground=PASS_C)
        self.log_txt.tag_configure("warn", foreground=WARN_C)
        self.log_txt.tag_configure("fail", foreground=FAIL_C)
        self.log_txt.tag_configure("info", foreground=ACCENT2)
        self.log_txt.tag_configure("dim",  foreground=MUTED)

    # ── Auto-test toggle ─────────────────────────────────────────────────────
    def _on_auto_toggle(self):
        if not self.auto_test.get():
            self._auto_watching = False
            self.auto_status_lbl.config(text="")

    # ── Link state polling ───────────────────────────────────────────────────
    def _poll_link(self):
        for attr, dot in self._link_dots.items():
            cb = getattr(self, attr)
            idx = cb.current()
            if idx >= 0 and idx < len(self.adapters):
                name = self.adapters[idx]["name"]
                up   = is_link_up(name)
                col  = PASS_C if up else FAIL_C
            else:
                col = MUTED
            dot.itemconfig("dot", fill=col)
        self.after(1500, self._poll_link)

    # ── Packet grid ──────────────────────────────────────────────────────────
    def _reset_grid(self):
        self._pkt_state = ["idle"] * PACKET_COUNT
        for cell, num in self._pkt_cells:
            cell.configure(bg=PKT_PEND)
            num.configure(bg=PKT_PEND, fg=DIM)
        for k, v in self._metric_vars.items():
            v.set("0" if k != "rtt_live" else "—")
        self.progress["value"] = 0
        self.prog_lbl.config(text="")

    def _on_packet(self, seq, status, rtt):
        self._pkt_state[seq] = status
        cell, num = self._pkt_cells[seq]
        if status == "ok":
            cell.configure(bg=PKT_OK)
            num.configure(bg=PKT_OK, fg="#0a2a14")
        else:
            cell.configure(bg=PKT_MISS)
            num.configure(bg=PKT_MISS, fg="#2a0a0a")

        sent = sum(1 for s in self._pkt_state if s != "idle")
        recv = self._pkt_state.count("ok")
        miss = self._pkt_state.count("miss")
        self._metric_vars["sent"].set(str(sent))
        self._metric_vars["recv"].set(str(recv))
        self._metric_vars["miss"].set(str(miss))
        if rtt:
            self._metric_vars["rtt_live"].set(f"{rtt:.1f}")
        self.progress["value"] = sent
        self.prog_lbl.config(text=f"{sent}/{PACKET_COUNT} packets")

    # ── Log ─────────────────────────────────────────────────────────────────
    def _append_log(self, msg, tag="dim"):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_txt.configure(state="normal")
        self.log_txt.insert("end", f"[{ts}]  ", "dim")
        self.log_txt.insert("end", msg + "\n", tag)
        self.log_txt.see("end")
        self.log_txt.configure(state="disabled")

    def _clear_log(self):
        self.log_txt.configure(state="normal")
        self.log_txt.delete("1.0","end")
        self.log_txt.configure(state="disabled")

    # ── Cable ID ─────────────────────────────────────────────────────────────
    def _update_cable_id(self):
        prefix = self.prefix_var.get().strip() or "CABLE"
        self.id_var.set(f"{prefix}-{self.cable_num:03d}")

    # ── Session stats ────────────────────────────────────────────────────────
    def _update_session(self, result, rtt_avg):
        self._sess_total += 1
        if result == "PASS":   self._sess_pass += 1
        elif result == "WARN": self._sess_warn += 1
        else:                  self._sess_fail += 1
        if rtt_avg: self._sess_rtts.append(rtt_avg)

        rate = f"{round(self._sess_pass / self._sess_total * 100)}%" \
               if self._sess_total else "—"
        self._sess_labels["total"].set(str(self._sess_total))
        self._sess_labels["pass"].set(str(self._sess_pass))
        self._sess_labels["warn"].set(str(self._sess_warn))
        self._sess_labels["fail"].set(str(self._sess_fail))
        self._sess_labels["rate"].set(rate)

    # ── Test runner ──────────────────────────────────────────────────────────
    def _start_test(self):
        if self.testing: return
        ai = self.combo_a.current()
        bi = self.combo_b.current()
        if ai < 0 or bi < 0:
            self.result_title.config(text="!", fg=WARN_C)
            self.result_cable.config(text="Select both adapters", fg=WARN_C)
            return
        if ai == bi:
            self.result_title.config(text="!", fg=WARN_C)
            self.result_cable.config(text="End A and End B must be different", fg=WARN_C)
            return

        adapter_a = self.adapters[ai]["name"]
        adapter_b = self.adapters[bi]["name"]
        cable_id  = self.id_var.get().strip() or f"CABLE-{self.cable_num:03d}"

        self.testing = True
        self.test_btn.config(state="disabled", text="Testing…", bg=BG4)
        self._reset_grid()
        self._clear_log()
        self.banner.configure(highlightbackground=BORDER)
        self.result_title.config(text="…", fg=MUTED)
        self.result_cable.config(text=f"testing {cable_id}", fg=MUTED)
        self.result_fault.config(text="")
        self.consec_lbl.config(text="")
        for v in self.stat_vars.values(): v.set("—")

        def pkt_cb(seq, status, rtt):
            self.after(0, lambda s=seq,st=status,r=rtt: self._on_packet(s,st,r))

        def log_cb(msg):
            tag = "ok" if "PASS" in msg or "ready" in msg.lower() or "sent" in msg.lower() \
                  else "fail" if "FAIL" in msg \
                  else "warn" if "WARN" in msg \
                  else "info" if "Sniffer" in msg or "Sending" in msg \
                  else "dim"
            self.after(0, lambda m=msg,t=tag: self._append_log(m, t))

        def run():
            result = run_loopback_test(adapter_a, adapter_b, cable_id, pkt_cb, log_cb)
            log_result(result)
            self.after(0, lambda: self._show_result(result))

        threading.Thread(target=run, daemon=True).start()

    def _show_result(self, r):
        self.testing = False
        self.test_btn.config(state="normal", text="Run Test  →", bg=ACCENT)

        result = r["result"]
        col    = {"PASS": PASS_C, "WARN": WARN_C, "FAIL": FAIL_C}[result]
        symbol = {"PASS": "✓  PASS", "WARN": "⚠  WARN", "FAIL": "✗  FAIL"}[result]

        self.banner.configure(highlightbackground=col)
        self.result_title.config(text=symbol, fg=col)
        self.result_cable.config(text=r["cable_id"], fg=TEXT)
        self.result_fault.config(
            text=r["fault_reason"] if r["fault_reason"] else "all checks passed",
            fg=WARN_C if r["fault_reason"] else MUTED)

        self.stat_vars["link"].set(
            f"A: {r['link_speed_a_mbps']} Mbps   B: {r['link_speed_b_mbps']} Mbps")
        self.stat_vars["packets"].set(
            f"{r['packets_received']}/{r['packets_sent']}  ({r['packet_loss_pct']}% loss)")
        self.stat_vars["rtt"].set(
            f"avg {r['rtt_avg_ms']}ms   min {r['rtt_min_ms']}ms   max {r['rtt_max_ms']}ms"
            if r["rtt_avg_ms"] else "—")
        self.stat_vars["errors"].set(
            f"A in:{r['errors_in_a']} out:{r['errors_out_a']}   "
            f"B in:{r['errors_in_b']} out:{r['errors_out_b']}")
        self.stat_vars["fault"].set(r["fault_reason"] or "none")

        # history
        rtt_str = f"{r['rtt_avg_ms']}ms" if r["rtt_avg_ms"] else "—"
        self.tree.insert("", 0,
            values=(r["cable_id"], result,
                    f"{r['packet_loss_pct']}%", rtt_str,
                    r["fault_reason"] or ""),
            tags=(result,))

        # session stats
        self._update_session(result, r["rtt_avg_ms"])

        # consecutive fail warning
        if result == "FAIL":
            self._consec_fail += 1
        else:
            self._consec_fail = 0

        if self._consec_fail >= 3:
            self.consec_lbl.config(
                text=f"⚠  {self._consec_fail} consecutive failures — check adapter selection or connections")
        else:
            self.consec_lbl.config(text="")

        # sound
        if self.sound_on.get():
            threading.Thread(target=beep, args=(result,), daemon=True).start()

        # advance cable ID
        self.cable_num += 1
        self._update_cable_id()

        # auto-test — wait for unplug then replug
        if self.auto_test.get():
            self._auto_watching = True
            self.auto_status_lbl.config(text="⏳  waiting for cable to be unplugged…")
            self.after(400, lambda: self._auto_watch("wait_unplug"))

    def _auto_watch(self, state):
        """
        Poll link state for the auto-test cycle.
        state: "wait_unplug" → "wait_replug" → fires _start_test
        """
        if not self.auto_test.get() or self.testing:
            self._auto_watching = False
            self.auto_status_lbl.config(text="")
            return

        ai = self.combo_a.current()
        bi = self.combo_b.current()
        if ai < 0 or bi < 0 or ai >= len(self.adapters) or bi >= len(self.adapters):
            self.after(500, lambda: self._auto_watch(state))
            return

        a_up = is_link_up(self.adapters[ai]["name"])
        b_up = is_link_up(self.adapters[bi]["name"])
        both_up   = a_up and b_up
        either_down = not a_up or not b_up

        if state == "wait_unplug":
            if either_down:
                # cable pulled — now wait for it to come back
                self.auto_status_lbl.config(
                    text="🔌  cable removed — plug in next cable…")
                self.after(400, lambda: self._auto_watch("wait_replug"))
            else:
                self.after(400, lambda: self._auto_watch("wait_unplug"))

        elif state == "wait_replug":
            if both_up:
                # link is up but needs time to fully negotiate — wait then verify
                self.auto_status_lbl.config(text="⚡  link up — letting connection settle…")
                self._auto_watching = False
                self.after(4000, self._auto_verify_then_start)
            else:
                self.after(400, lambda: self._auto_watch("wait_replug"))

    def _auto_verify_then_start(self):
        """Check both adapters have actually negotiated full speed before firing."""
        ai = self.combo_a.current()
        bi = self.combo_b.current()
        if ai < 0 or bi < 0 or not self.auto_test.get():
            self.auto_status_lbl.config(text="")
            return

        a_speed = get_link_speed(self.adapters[ai]["name"])
        b_speed = get_link_speed(self.adapters[bi]["name"])

        if a_speed >= 100 and b_speed >= 100:
            self.auto_status_lbl.config(
                text=f"⚡  {a_speed}Mbps negotiated — starting test…")
            self.after(300, self._auto_start)
        else:
            # still negotiating — check again shortly
            self.auto_status_lbl.config(text="⚡  link up — waiting for speed negotiation…")
            self.after(500, self._auto_verify_then_start)

    def _auto_start(self):
        self.auto_status_lbl.config(text="")
        self._start_test()

# ── Entry ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if os.name == "nt" and not ctypes.windll.shell32.IsUserAnAdmin():
        import tkinter.messagebox as mb
        r = tk.Tk(); r.withdraw()
        mb.showerror("Admin required",
                     "Run cablecheck as Administrator\n(raw socket access needed)")
        sys.exit(1)
    App().mainloop()
