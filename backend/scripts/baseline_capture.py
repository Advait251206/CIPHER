"""
CIPHER Baseline Traffic Capture
Standalone script to capture normal network traffic for a set duration
and export the extracted 67 CIC-IDS2017 features to a CSV file.
"""

import sys
import time
import signal
import argparse
import logging
import threading
import csv
from pathlib import Path

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.network.live_sensor.config import SensorConfig
from app.network.live_sensor.flow_tracker import FlowTracker
from app.network.live_sensor.feature_builder import LiveFeatureBuilder, EXPECTED_67_FEATURES
from app.network.live_sensor.packet_capture import (
    PacketCapture,
    get_available_interfaces,
    is_npcap_available,
    SCAPY_AVAILABLE
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("cipher.baseline")

def list_interfaces_and_exit():
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
    print("\nRun with --interface \"<name>\" to start capturing.")
    sys.exit(0)

class BaselineCaptureService:
    def __init__(self, interface: str, output_csv: str, bpf_filter: str):
        self.interface = interface
        self.output_csv = output_csv
        self.bpf_filter = bpf_filter
        
        self.config = SensorConfig()
        self.flow_tracker = FlowTracker(self.config)
        self.feature_builder = LiveFeatureBuilder()
        
        self.packet_capture = PacketCapture(
            on_packet=self.flow_tracker.process_packet,
            interface=self.interface,
            bpf_filter=self.bpf_filter
        )
        
        self._running = False
        self._worker_thread = None
        self._lock = threading.Lock()
        
        # Open CSV file and write header
        self._csv_file = open(self.output_csv, 'w', newline='', encoding='utf-8')
        self._csv_writer = csv.writer(self._csv_file)
        
        self._header = [
            "Source IP", "Source Port", "Destination IP", "Destination Port", "Protocol", "Timestamp"
        ] + EXPECTED_67_FEATURES
        self._csv_writer.writerow(self._header)
        
        self.total_flows_written = 0

    def start(self):
        logger.info(f"Starting packet capture on {self.interface}...")
        self.packet_capture.start()
        
        self._running = True
        self._worker_thread = threading.Thread(target=self._flow_harvest_worker, name="baseline-harvester")
        self._worker_thread.daemon = True
        self._worker_thread.start()
        logger.info("Baseline capture active. Waiting for flows...")

    def stop(self):
        logger.info("Stopping baseline capture...")
        self._running = False
        self.packet_capture.stop()
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=2.0)
            
        # Flush any remaining flows
        final_flows = self.flow_tracker.get_expired_flows()
        self._process_expired_flows(final_flows)
        
        self._csv_file.close()
        logger.info(f"Capture stopped. Wrote {self.total_flows_written} flows to {self.output_csv}")

    def _flow_harvest_worker(self):
        while self._running:
            try:
                expired_flows = self.flow_tracker.get_expired_flows()
                if expired_flows:
                    self._process_expired_flows(expired_flows)
            except Exception as e:
                logger.error(f"Error harvesting flows: {e}")
            time.sleep(1.0)
            
    def _process_expired_flows(self, flows):
        with self._lock:
            for flow in flows:
                features, completeness = LiveFeatureBuilder.build_features(flow)
                
                # We want only valid network flows (Completeness > 0)
                if completeness <= 0:
                    continue
                    
                row = [
                    flow.src_ip,
                    flow.src_port,
                    flow.dst_ip,
                    flow.dst_port,
                    flow.protocol,
                    flow.start_time
                ]
                
                # Append the 67 features in exact order
                for feature_name in EXPECTED_67_FEATURES:
                    row.append(features.get(feature_name, 0.0))
                    
                self._csv_writer.writerow(row)
                self.total_flows_written += 1
            self._csv_file.flush()

def main():
    parser = argparse.ArgumentParser(description="CIPHER Baseline Traffic Capture")
    parser.add_argument("--list-interfaces", action="store_true", help="List available network interfaces and exit")
    parser.add_argument("--interface", "-i", type=str, default=None, help="Interface name, description, or IP to monitor")
    parser.add_argument("--bpf", "-b", type=str, default="ip or ip6", help="BPF capture filter (default: 'ip or ip6')")
    parser.add_argument("--duration", "-d", type=int, default=3600, help="Duration to run in seconds (default: 3600 = 1 hr)")
    parser.add_argument("--output", "-o", type=str, default="baseline_traffic.csv", help="Output CSV filename")
    
    args = parser.parse_args()

    if args.list_interfaces or not args.interface:
        list_interfaces_and_exit()
        
    # REPO_ROOT is backend directory since __file__ is in backend/scripts
    output_path = REPO_ROOT / args.output

    print("=" * 70)
    print("      CIPHER BASELINE TRAFFIC CAPTURE")
    print("=" * 70)
    print(f"[*] Target Interface : {args.interface}")
    print(f"[*] BPF Filter       : {args.bpf}")
    print(f"[*] Duration         : {args.duration} seconds")
    print(f"[*] Output CSV       : {output_path}")
    print("-" * 70)

    service = BaselineCaptureService(
        interface=args.interface,
        output_csv=str(output_path),
        bpf_filter=args.bpf
    )

    def signal_handler(sig, frame):
        print("\n\n[!] Interrupted by user. Saving data...")
        service.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        service.start()
        start_time = time.time()
        
        while True:
            elapsed = time.time() - start_time
            if elapsed >= args.duration:
                print(f"\n[+] Reached target duration of {args.duration}s. Shutting down...")
                break
            
            # Print a status update every 10 seconds
            if int(elapsed) % 10 == 0:
                print(f"[{int(elapsed)}s / {args.duration}s] Flows Captured: {service.total_flows_written}", end="\r")
            
            time.sleep(1)
            
    except Exception as e:
        logger.error(f"Fatal error: {e}")
    finally:
        service.stop()

if __name__ == "__main__":
    main()
