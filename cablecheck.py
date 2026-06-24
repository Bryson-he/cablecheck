"""
cablecheck.py — Dual-NIC loopback cable tester
Sends raw traffic across a cable via two adapters on the same machine,
reads NIC error counters, and logs pass/fail + diagnostics to CSV.

Requirements:
    pip install scapy psutil rich
    Run as Administrator (raw socket access)
"""

import csv
import os
import sys
import time
import uuid
import argparse
import threading
import subprocess
import ctypes
from datetime import datetime
from pathlib import Path

try:
    import psutil
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
    from rich import box
    from scapy.all import (
        Ether, IP, UDP, Raw,
        sendp, sniff, get_if_list, conf
    )
except ImportError:
    print("Missing dependencies. Run: pip install scapy psutil rich")
    sys.exit(1)

console = Console()

LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / f"cablecheck_{datetime.now().strftime('%Y%m%d')}.csv"

CSV_HEADERS = [
    "timestamp", "cable_id", "adapter_a", "adapter_b",
    "link_speed_a_mbps", "link_speed_b_mbps",
    "packets_sent", "packets_received", "packet_loss_pct",
    "rtt_avg_ms", "rtt_min_ms", "rtt_max_ms",
    "errors_in_a", "errors_out_a", "errors_in_b", "errors_out_b",
    "result", "fault_reason"
]

PACKET_COUNT   = 50
PACKET_TIMEOUT = 3.0   # seconds to wait for echo
TEST_PORT      = 59876
MAGIC          = b"CABLECHECK"


# ── NIC utilities ────────────────────────────────────────────────────────────

def get_adapters():
    """Return list of (name, friendly_name, speed_mbps) for UP ethernet adapters."""
    adapters = []
    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()
    for name, stat in stats.items():
        if stat.isup and stat.speed > 0:
            # Skip loopback and Wi-Fi (heuristic: speed usually ≠ 54/300/867)
            friendly = name
            adapters.append({
                "name":    name,
                "speed":   stat.speed,
                "mtu":     stat.mtu,
            })
    return adapters


def get_nic_counters(adapter_name):
    counters = psutil.net_io_counters(pernic=True)
    c = counters.get(adapter_name)
    if c is None:
        return {"errin": 0, "errout": 0, "dropin": 0, "dropout": 0}
    return {
        "errin":   c.errin,
        "errout":  c.errout,
        "dropin":  c.dropin,
        "dropout": c.dropout,
    }


def counter_delta(before, after):
    return {k: after[k] - before[k] for k in before}


def get_link_speed(adapter_name):
    stats = psutil.net_if_stats()
    s = stats.get(adapter_name)
    return s.speed if s else 0


# ── Packet test ───────────────────────────────────────────────────────────────

def get_mac(adapter_name):
    addrs = psutil.net_if_addrs()
    for addr in addrs.get(adapter_name, []):
        if addr.family == psutil.AF_LINK if hasattr(psutil, 'AF_LINK') else 17:
            return addr.address
    return "ff:ff:ff:ff:ff:ff"


def run_loopback_test(adapter_a: str, adapter_b: str, cable_id: str):
    """
    Send PACKET_COUNT tagged UDP frames out adapter_a.
    Sniff them on adapter_b, measure RTT and loss.
    Also captures NIC error counter deltas on both sides.
    """

    session_id = uuid.uuid4().bytes[:4]
    received   = {}
    lock       = threading.Lock()
    rtts       = []

    # Baseline counters
    before_a = get_nic_counters(adapter_a)
    before_b = get_nic_counters(adapter_b)

    send_times = {}

    def build_packet(seq: int) -> bytes:
        payload = MAGIC + session_id + seq.to_bytes(2, "big")
        return Ether(dst="ff:ff:ff:ff:ff:ff") / \
               IP(dst="192.168.99.1") / \
               UDP(dport=TEST_PORT, sport=TEST_PORT) / \
               Raw(load=payload)

    def packet_handler(pkt):
        try:
            raw = bytes(pkt[Raw].load)
            if not raw.startswith(MAGIC):
                return
            sid  = raw[len(MAGIC):len(MAGIC)+4]
            if sid != session_id:
                return
            seq  = int.from_bytes(raw[len(MAGIC)+4:len(MAGIC)+6], "big")
            rx_t = time.perf_counter()
            with lock:
                if seq in send_times and seq not in received:
                    rtt = (rx_t - send_times[seq]) * 1000
                    received[seq] = rtt
                    rtts.append(rtt)
        except Exception:
            pass

    # Start sniffer on adapter_b in background
    stop_sniff = threading.Event()

    def sniffer():
        sniff(
            iface=adapter_b,
            filter=f"udp port {TEST_PORT}",
            prn=packet_handler,
            store=False,
            stop_filter=lambda _: stop_sniff.is_set(),
            timeout=PACKET_TIMEOUT + 2,
        )

    sniffer_thread = threading.Thread(target=sniffer, daemon=True)
    sniffer_thread.start()
    time.sleep(0.3)  # let sniffer bind

    # Send packets
    for seq in range(PACKET_COUNT):
        pkt = build_packet(seq)
        send_times[seq] = time.perf_counter()
        sendp(pkt, iface=adapter_a, verbose=False)
        time.sleep(0.02)

    time.sleep(PACKET_TIMEOUT)
    stop_sniff.set()
    sniffer_thread.join(timeout=3)

    # Delta counters
    after_a  = get_nic_counters(adapter_a)
    after_b  = get_nic_counters(adapter_b)
    delta_a  = counter_delta(before_a, after_a)
    delta_b  = counter_delta(before_b, after_b)

    # Results
    rx_count = len(received)
    loss_pct = round((PACKET_COUNT - rx_count) / PACKET_COUNT * 100, 1)

    rtt_avg = round(sum(rtts) / len(rtts), 2) if rtts else None
    rtt_min = round(min(rtts), 2) if rtts else None
    rtt_max = round(max(rtts), 2) if rtts else None

    speed_a  = get_link_speed(adapter_a)
    speed_b  = get_link_speed(adapter_b)

    # Determine result
    fault = None
    if rx_count == 0:
        result = "FAIL"
        fault  = "No packets received — open circuit or no link"
    elif loss_pct > 5:
        result = "FAIL"
        fault  = f"{loss_pct}% packet loss — bad crimp or marginal cable"
    elif delta_a["errin"] + delta_a["errout"] + delta_b["errin"] + delta_b["errout"] > 5:
        result = "WARN"
        fault  = "Elevated NIC error counters — possible split pair or poor termination"
    elif rtt_avg and rtt_avg > 10:
        result = "WARN"
        fault  = f"High avg RTT {rtt_avg}ms — cable may be marginal length or quality"
    elif speed_a < 1000 or speed_b < 1000:
        result = "WARN"
        fault  = f"Link negotiated below Gigabit (A:{speed_a}Mbps B:{speed_b}Mbps) — check pairs 4,5,7,8"
    else:
        result = "PASS"

    return {
        "timestamp":         datetime.now().isoformat(timespec="seconds"),
        "cable_id":          cable_id,
        "adapter_a":         adapter_a,
        "adapter_b":         adapter_b,
        "link_speed_a_mbps": speed_a,
        "link_speed_b_mbps": speed_b,
        "packets_sent":      PACKET_COUNT,
        "packets_received":  rx_count,
        "packet_loss_pct":   loss_pct,
        "rtt_avg_ms":        rtt_avg,
        "rtt_min_ms":        rtt_min,
        "rtt_max_ms":        rtt_max,
        "errors_in_a":       delta_a["errin"],
        "errors_out_a":      delta_a["errout"],
        "errors_in_b":       delta_b["errin"],
        "errors_out_b":      delta_b["errout"],
        "result":            result,
        "fault_reason":      fault or "",
    }


# ── CSV logging ───────────────────────────────────────────────────────────────

def init_csv():
    if not LOG_FILE.exists():
        with open(LOG_FILE, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_HEADERS)
            writer.writeheader()


def log_result(result: dict):
    with open(LOG_FILE, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_HEADERS)
        writer.writerow(result)


# ── Display ───────────────────────────────────────────────────────────────────

def print_result(r: dict):
    colour = {"PASS": "green", "WARN": "yellow", "FAIL": "red"}[r["result"]]
    symbol = {"PASS": "✓", "WARN": "⚠", "FAIL": "✗"}[r["result"]]

    table = Table(box=box.SIMPLE_HEAD, show_header=False, padding=(0, 1))
    table.add_column(style="dim", width=22)
    table.add_column()

    table.add_row("Cable ID",      r["cable_id"])
    table.add_row("Adapter A",     r["adapter_a"])
    table.add_row("Adapter B",     r["adapter_b"])
    table.add_row("Link speed",    f"A: {r['link_speed_a_mbps']} Mbps  |  B: {r['link_speed_b_mbps']} Mbps")
    table.add_row("Packets",       f"{r['packets_received']}/{r['packets_sent']} received  ({r['packet_loss_pct']}% loss)")
    if r["rtt_avg_ms"]:
        table.add_row("RTT",       f"avg {r['rtt_avg_ms']}ms  min {r['rtt_min_ms']}ms  max {r['rtt_max_ms']}ms")
    table.add_row("NIC errors A",  f"in:{r['errors_in_a']}  out:{r['errors_out_a']}")
    table.add_row("NIC errors B",  f"in:{r['errors_in_b']}  out:{r['errors_out_b']}")
    if r["fault_reason"]:
        table.add_row("Fault",     f"[yellow]{r['fault_reason']}[/yellow]")

    console.print(Panel(
        table,
        title=f"[{colour}]{symbol} {r['result']}[/{colour}]  —  {r['cable_id']}",
        border_style=colour,
    ))


def pick_adapters():
    adapters = get_adapters()
    if len(adapters) < 2:
        console.print("[red]Need at least 2 active ethernet adapters. Plug in USB-to-ethernet and try again.[/red]")
        sys.exit(1)

    console.print("\n[bold]Available adapters:[/bold]")
    for i, a in enumerate(adapters):
        console.print(f"  [{i}] {a['name']}  ({a['speed']} Mbps)")

    console.print()
    a_idx = int(console.input("Select [bold]End A[/bold] adapter index (built-in ethernet): "))
    b_idx = int(console.input("Select [bold]End B[/bold] adapter index (USB ethernet):     "))
    return adapters[a_idx]["name"], adapters[b_idx]["name"]


# ── Main loop ─────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="cablecheck — dual-NIC loopback cable tester")
    parser.add_argument("--adapter-a", help="Adapter A name (skip interactive picker)")
    parser.add_argument("--adapter-b", help="Adapter B name (skip interactive picker)")
    parser.add_argument("--count",     type=int, default=50, help="Packets per test (default 50)")
    parser.add_argument("--batch",     action="store_true", help="Run continuously, auto-increment cable IDs")
    args = parser.parse_args()

    global PACKET_COUNT
    PACKET_COUNT = args.count

    console.print(Panel.fit(
        "[bold]cablecheck[/bold]  —  dual-NIC loopback cable tester\n"
        "[dim]Plug both ends of the cable into this machine and hit Enter[/dim]",
        border_style="blue",
    ))

    init_csv()

    if args.adapter_a and args.adapter_b:
        adapter_a, adapter_b = args.adapter_a, args.adapter_b
    else:
        adapter_a, adapter_b = pick_adapters()

    console.print(f"\n[dim]Logging to:[/dim] {LOG_FILE}\n")

    cable_num = 1

    while True:
        cable_id = f"CABLE-{cable_num:03d}"

        if not args.batch:
            raw = console.input(f"Cable ID [[bold]{cable_id}[/bold]] (Enter to accept, or type ID, Q to quit): ").strip()
            if raw.lower() == "q":
                break
            if raw:
                cable_id = raw

        console.print(f"\n[dim]Testing {cable_id}...[/dim]")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total} packets"),
            transient=True,
        ) as progress:
            task = progress.add_task("Sending test packets", total=PACKET_COUNT)
            # Run test (progress is approximate — updates after test completes)
            result = run_loopback_test(adapter_a, adapter_b, cable_id)
            progress.update(task, completed=result["packets_sent"])

        print_result(result)
        log_result(result)

        cable_num += 1

        if not args.batch:
            again = console.input("\nTest another cable? [Y/n]: ").strip().lower()
            if again == "n":
                break

    console.print(f"\n[green]Done.[/green] Results saved to [bold]{LOG_FILE}[/bold]")


if __name__ == "__main__":
    if os.name == "nt" and not ctypes.windll.shell32.IsUserAnAdmin():
        console.print("[red]Run as Administrator (required for raw socket access)[/red]")
        sys.exit(1)
    import ctypes
    main()
