"""
CIPHER Live Network Sensor Demo Console
Interactive, safe, local-first demonstration of real packet capture,
bidirectional flow aggregation, and CIPHER Network IDS pipeline evaluation.

Safe Defaults:
- Live sensor defaults to detect_only and does not modify the host firewall unless an explicit enforcement mode is configured
- Live packet capture runs in user space through Scapy/Npcap; depending on the Windows interface and Npcap configuration, packet capture may require elevated privileges
- zero payload logging or persistence
- clean graceful shutdown on Ctrl+C
"""

import sys
import time
import signal
import argparse
import logging
from pathlib import Path
from datetime import datetime

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("cipher.demo")

from app.network.live_sensor import (
    LiveSensorService,
    get_available_interfaces,
    is_npcap_available,
    SCAPY_AVAILABLE
)


def print_banner():
    print("=" * 70)
    print("      CIPHER LIVE NETWORK INTRUSION DETECTION SENSOR")
    print("  Local-First • Privacy-Preserving • 67-Feature CIC Pipeline")
    print("=" * 70)


def list_interfaces_and_exit():
    print_banner()
    if not SCAPY_AVAILABLE:
        print("[ERROR] Scapy is not installed. Run: pip install scapy>=2.7.0")
        sys.exit(1)

    if not is_npcap_available():
        print("[WARNING] Npcap not detected or not running in WinPcap-compatible mode.")

    ifaces = get_available_interfaces()
    print(f"\nDiscovered {len(ifaces)} Network Interfaces:\n")
    print(f"{'#':<3} {'Interface Name':<28} {'IP Address':<18} {'Status':<10} {'Description'}")
    print("-" * 90)
    for idx, iface in enumerate(ifaces, 1):
        name = iface['name'][:26]
        addr = iface['address'][:16] or "N/A"
        desc = iface['description'][:30]
        status = iface['status']
        print(f"{idx:<3} {name:<28} {addr:<18} {status:<10} {desc}")
    print("-" * 90)
    print("\nRun with --interface \"<name>\" to start monitoring.")
    sys.exit(0)


def main():
    parser = argparse.ArgumentParser(description="CIPHER Live Network Sensor Console")
    parser.add_argument("--list-interfaces", action="store_true", help="List available network interfaces and exit")
    parser.add_argument("--interface", "-i", type=str, default=None, help="Interface name, description, or IP to monitor")
    parser.add_argument("--bpf", "-b", type=str, default="ip", help="BPF capture filter (default: 'ip')")
    parser.add_argument("--idle-timeout", type=float, default=5.0, help="Flow idle timeout in seconds (default: 5.0)")
    parser.add_argument("--active-timeout", type=float, default=60.0, help="Flow active timeout in seconds (default: 60.0)")
    args = parser.parse_args()

    if args.list_interfaces or not args.interface:
        list_interfaces_and_exit()

    print_banner()
    print(f"[*] Target Interface : {args.interface}")
    print(f"[*] BPF Filter       : {args.bpf}")
    print(f"[*] Flow Idle Timeout: {args.idle_timeout}s")
    print(f"[*] Active Timeout   : {args.active_timeout}s")
    print(f"[*] Prevention Policy: Defaults to detect_only (no firewall modifications unless enforcement configured)")
    print(f"[*] Privacy Guarantee: Metadata/Statistics only (Zero payload capture)")
    print("-" * 70)

    sensor = LiveSensorService()

    # Graceful shutdown handler
    def signal_handler(sig, frame):
        print("\n\n[!] Stopping live sensor gracefully...")
        status = sensor.stop()
        print("\n" + "=" * 70)
        print("                 FINAL SENSOR METRICS")
        print("=" * 70)
        print(f"  Packets Captured  : {status.get('packets_captured', 0):,}")
        print(f"  Completed Flows   : {status.get('completed_flows', 0):,}")
        print(f"  Analyzed Flows    : {status.get('analyzed_flows', 0):,}")
        print(f"  Detected Attacks  : {status.get('detected_attacks', 0):,}")
        print(f"  Runtime Errors    : {status.get('errors', 0):,}")
        print("=" * 70)
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    try:
        sensor.start(
            interface=args.interface,
            bpf_filter=args.bpf,
            flow_idle_timeout=args.idle_timeout,
            flow_active_timeout=args.active_timeout
        )
        print("[+] Live sensor running. Press Ctrl+C to terminate.\n")
    except Exception as e:
        logger.error(f"Failed to start live sensor: {e}")
        sys.exit(1)

    # Live console telemetry loop
    try:
        last_pkts = 0
        while True:
            time.sleep(2.0)
            st = sensor.get_status()
            pkts = st.get("packets_captured", 0)
            active = st.get("active_flows", 0)
            comp = st.get("completed_flows", 0)
            analyzed = st.get("analyzed_flows", 0)
            attacks = st.get("detected_attacks", 0)
            rate = (pkts - last_pkts) / 2.0
            last_pkts = pkts

            now_str = datetime.now().strftime("%H:%M:%S")
            print(
                f"[{now_str}] Pkts: {pkts:>6} ({rate:>5.1f} pps) | "
                f"Active Flows: {active:>3} | Completed: {comp:>3} | "
                f"Analyzed: {analyzed:>3} | Attacks: {attacks:>2}"
            )
    except KeyboardInterrupt:
        signal_handler(None, None)


if __name__ == "__main__":
    main()
