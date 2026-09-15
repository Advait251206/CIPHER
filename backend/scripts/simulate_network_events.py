"""
CIPHER Safe Network Event Simulator
Generates realistic, synthetic network flow profiles representing:
- Normal (Benign Web Traffic)
- Port Scan (Half-open SYN probes across ports)
- Denial of Service (DoS volumetric packet burst)
- Distributed Denial of Service (DDoS uniform flood)
- Brute Force (SSH/FTP authentication churn)

Sends flows through the CIPHER Network IDPS detection pipeline (in-process or REST API)
to validate detection, threat scoring, and IPS response without creating any real network hazards.
"""

import os
import sys
import time
import json
import argparse
from typing import Dict, Any, List

# Ensure backend is on python path
current_dir = os.path.dirname(os.path.abspath(__file__))
backend_root = os.path.dirname(current_dir) if "scripts" in current_dir else current_dir
if backend_root not in sys.path:
    sys.path.insert(0, backend_root)

from app.network.schemas import NetworkFlowAnalyzeRequest
from app.network.service import NetworkService


def generate_synthetic_flow(scenario: str, seq_num: int = 0) -> NetworkFlowAnalyzeRequest:
    """Creates a realistic synthetic flow matching the scenario."""

    if scenario == "NORMAL":
        # Standard HTTPS web browsing session
        features = {
            "Destination Port": 443,
            "Flow Duration": 125000,           # 125ms
            "Total Fwd Packets": 18,
            "Total Backward Packets": 24,
            "Total Length of Fwd Packets": 2850,
            "Total Length of Bwd Packets": 24300,
            "Fwd Packet Length Max": 1460,
            "Fwd Packet Length Min": 40,
            "Fwd Packet Length Mean": 158.3,
            "Fwd Packet Length Std": 320.1,
            "Bwd Packet Length Max": 1460,
            "Bwd Packet Length Min": 40,
            "Bwd Packet Length Mean": 1012.5,
            "Bwd Packet Length Std": 450.2,
            "Flow Bytes/s": 217200.0,
            "Flow Packets/s": 336.0,
            "Flow IAT Mean": 3048.0,
            "Flow IAT Std": 2100.0,
            "Flow IAT Max": 18000.0,
            "Flow IAT Min": 12.0,
            "Fwd IAT Total": 120000.0,
            "Fwd IAT Mean": 7058.0,
            "Fwd IAT Std": 3100.0,
            "Fwd IAT Max": 18000.0,
            "Fwd IAT Min": 12.0,
            "Bwd IAT Total": 124000.0,
            "Bwd IAT Mean": 5391.0,
            "Bwd IAT Std": 2400.0,
            "Bwd IAT Max": 17500.0,
            "Bwd IAT Min": 15.0,
            "Fwd PSH Flags": 1,
            "Fwd Header Length": 360,
            "Bwd Header Length": 480,
            "Fwd Packets/s": 144.0,
            "Bwd Packets/s": 192.0,
            "Min Packet Length": 40,
            "Max Packet Length": 1460,
            "Packet Length Mean": 646.4,
            "Packet Length Std": 580.2,
            "Packet Length Variance": 336632.0,
            "FIN Flag Count": 1,
            "SYN Flag Count": 1,
            "RST Flag Count": 0,
            "PSH Flag Count": 1,
            "ACK Flag Count": 1,
            "URG Flag Count": 0,
            "ECE Flag Count": 0,
            "Down/Up Ratio": 1.0,
            "Average Packet Size": 646.4,
            "Avg Fwd Segment Size": 158.3,
            "Avg Bwd Segment Size": 1012.5,
            "Subflow Fwd Packets": 18,
            "Subflow Fwd Bytes": 2850,
            "Subflow Bwd Packets": 24,
            "Subflow Bwd Bytes": 24300,
            "Init_Win_bytes_forward": 29200,
            "Init_Win_bytes_backward": 28960,
            "act_data_pkt_fwd": 8,
            "min_seg_size_forward": 20,
            "Active Mean": 0.0,
            "Active Std": 0.0,
            "Active Max": 0.0,
            "Active Min": 0.0,
            "Idle Mean": 0.0,
            "Idle Std": 0.0,
            "Idle Max": 0.0,
            "Idle Min": 0.0
        }
        return NetworkFlowAnalyzeRequest(
            source_ip="192.168.1.105",
            destination_ip="93.184.216.34",
            source_port=52310 + seq_num,
            destination_port=443,
            protocol="TCP",
            features=features
        )

    elif scenario == "PORT_SCAN":
        # Automated SYN port sweep probe
        probed_ports = [8080, 8443, 8000, 9000]
        target_port = probed_ports[seq_num % len(probed_ports)]

        features = {
            "Destination Port": target_port,
            "Flow Duration": 45,               # 45 microseconds
            "Total Fwd Packets": 1,
            "Total Backward Packets": 0,
            "Total Length of Fwd Packets": 0,
            "Total Length of Bwd Packets": 0,
            "Fwd Packet Length Max": 0,
            "Fwd Packet Length Min": 0,
            "Fwd Packet Length Mean": 0.0,
            "Fwd Packet Length Std": 0.0,
            "Bwd Packet Length Max": 0,
            "Bwd Packet Length Min": 0,
            "Bwd Packet Length Mean": 0.0,
            "Bwd Packet Length Std": 0.0,
            "Flow Bytes/s": 0.0,
            "Flow Packets/s": 22222.2,
            "Flow IAT Mean": 45.0,
            "Flow IAT Std": 0.0,
            "Flow IAT Max": 45.0,
            "Flow IAT Min": 45.0,
            "Fwd IAT Total": 45.0,
            "Fwd IAT Mean": 45.0,
            "Fwd IAT Std": 0.0,
            "Fwd IAT Max": 45.0,
            "Fwd IAT Min": 45.0,
            "Bwd IAT Total": 0.0,
            "Bwd IAT Mean": 0.0,
            "Bwd IAT Std": 0.0,
            "Bwd IAT Max": 0.0,
            "Bwd IAT Min": 0.0,
            "Fwd PSH Flags": 0,
            "Fwd Header Length": 20,
            "Bwd Header Length": 0,
            "Fwd Packets/s": 22222.2,
            "Bwd Packets/s": 0.0,
            "Min Packet Length": 0,
            "Max Packet Length": 0,
            "Packet Length Mean": 0.0,
            "Packet Length Std": 0.0,
            "Packet Length Variance": 0.0,
            "FIN Flag Count": 0,
            "SYN Flag Count": 1,              # SYN flag set
            "RST Flag Count": 0,
            "PSH Flag Count": 0,
            "ACK Flag Count": 0,              # No ACK
            "URG Flag Count": 0,
            "ECE Flag Count": 0,
            "Down/Up Ratio": 0.0,
            "Average Packet Size": 0.0,
            "Avg Fwd Segment Size": 0.0,
            "Avg Bwd Segment Size": 0.0,
            "Subflow Fwd Packets": 1,
            "Subflow Fwd Bytes": 0,
            "Subflow Bwd Packets": 0,
            "Subflow Bwd Bytes": 0,
            "Init_Win_bytes_forward": 1024,
            "Init_Win_bytes_backward": -1,
            "act_data_pkt_fwd": 0,
            "min_seg_size_forward": 20,
            "Active Mean": 0.0,
            "Active Std": 0.0,
            "Active Max": 0.0,
            "Active Min": 0.0,
            "Idle Mean": 0.0,
            "Idle Std": 0.0,
            "Idle Max": 0.0,
            "Idle Min": 0.0
        }
        return NetworkFlowAnalyzeRequest(
            source_ip="10.0.0.88",
            destination_ip="192.168.1.50",
            source_port=41000 + seq_num,
            destination_port=target_port,
            protocol="TCP",
            features=features
        )

    elif scenario == "DOS":
        # Volumetric HTTP DoS Flood
        features = {
            "Destination Port": 80,
            "Flow Duration": 15000,            # 15ms
            "Total Fwd Packets": 850,
            "Total Backward Packets": 0,
            "Total Length of Fwd Packets": 76500,
            "Total Length of Bwd Packets": 0,
            "Fwd Packet Length Max": 90,
            "Fwd Packet Length Min": 90,
            "Fwd Packet Length Mean": 90.0,
            "Fwd Packet Length Std": 0.0,
            "Bwd Packet Length Max": 0,
            "Bwd Packet Length Min": 0,
            "Bwd Packet Length Mean": 0.0,
            "Bwd Packet Length Std": 0.0,
            "Flow Bytes/s": 5100000.0,         # 5.1 MB/s
            "Flow Packets/s": 56666.7,         # 56.6k pkts/s
            "Flow IAT Mean": 17.6,
            "Flow IAT Std": 4.2,
            "Flow IAT Max": 35.0,
            "Flow IAT Min": 8.0,
            "Fwd IAT Total": 15000.0,
            "Fwd IAT Mean": 17.6,
            "Fwd IAT Std": 4.2,
            "Fwd IAT Max": 35.0,
            "Fwd IAT Min": 8.0,
            "Bwd IAT Total": 0.0,
            "Bwd IAT Mean": 0.0,
            "Bwd IAT Std": 0.0,
            "Bwd IAT Max": 0.0,
            "Bwd IAT Min": 0.0,
            "Fwd PSH Flags": 1,
            "Fwd Header Length": 17000,
            "Bwd Header Length": 0,
            "Fwd Packets/s": 56666.7,
            "Bwd Packets/s": 0.0,
            "Min Packet Length": 90,
            "Max Packet Length": 90,
            "Packet Length Mean": 90.0,
            "Packet Length Std": 0.0,
            "Packet Length Variance": 0.0,
            "FIN Flag Count": 0,
            "SYN Flag Count": 0,
            "RST Flag Count": 0,
            "PSH Flag Count": 1,
            "ACK Flag Count": 1,
            "URG Flag Count": 0,
            "ECE Flag Count": 0,
            "Down/Up Ratio": 0.0,
            "Average Packet Size": 90.0,
            "Avg Fwd Segment Size": 90.0,
            "Avg Bwd Segment Size": 0.0,
            "Subflow Fwd Packets": 850,
            "Subflow Fwd Bytes": 76500,
            "Subflow Bwd Packets": 0,
            "Subflow Bwd Bytes": 0,
            "Init_Win_bytes_forward": 29200,
            "Init_Win_bytes_backward": -1,
            "act_data_pkt_fwd": 850,
            "min_seg_size_forward": 20,
            "Active Mean": 0.0,
            "Active Std": 0.0,
            "Active Max": 0.0,
            "Active Min": 0.0,
            "Idle Mean": 0.0,
            "Idle Std": 0.0,
            "Idle Max": 0.0,
            "Idle Min": 0.0
        }
        return NetworkFlowAnalyzeRequest(
            source_ip="172.16.0.42",
            destination_ip="192.168.1.10",
            source_port=48220,
            destination_port=80,
            protocol="TCP",
            features=features
        )

    elif scenario == "DDOS":
        # High-rate distributed stream
        bot_ips = ["198.51.100.12", "198.51.100.13", "198.51.100.14", "198.51.100.15"]
        src = bot_ips[seq_num % len(bot_ips)]

        features = {
            "Destination Port": 80,
            "Flow Duration": 8000,
            "Total Fwd Packets": 400,
            "Total Backward Packets": 0,
            "Total Length of Fwd Packets": 32000,
            "Total Length of Bwd Packets": 0,
            "Fwd Packet Length Max": 80,
            "Fwd Packet Length Min": 80,
            "Fwd Packet Length Mean": 80.0,
            "Fwd Packet Length Std": 0.0,
            "Bwd Packet Length Max": 0,
            "Bwd Packet Length Min": 0,
            "Bwd Packet Length Mean": 0.0,
            "Bwd Packet Length Std": 0.0,
            "Flow Bytes/s": 4000000.0,
            "Flow Packets/s": 50000.0,
            "Flow IAT Mean": 20.0,
            "Flow IAT Std": 2.0,
            "Flow IAT Max": 30.0,
            "Flow IAT Min": 10.0,
            "Fwd IAT Total": 8000.0,
            "Fwd IAT Mean": 20.0,
            "Fwd IAT Std": 2.0,
            "Fwd IAT Max": 30.0,
            "Fwd IAT Min": 10.0,
            "Bwd IAT Total": 0.0,
            "Bwd IAT Mean": 0.0,
            "Bwd IAT Std": 0.0,
            "Bwd IAT Max": 0.0,
            "Bwd IAT Min": 0.0,
            "Fwd PSH Flags": 0,
            "Fwd Header Length": 8000,
            "Bwd Header Length": 0,
            "Fwd Packets/s": 50000.0,
            "Bwd Packets/s": 0.0,
            "Min Packet Length": 80,
            "Max Packet Length": 80,
            "Packet Length Mean": 80.0,
            "Packet Length Std": 0.0,
            "Packet Length Variance": 0.0,
            "FIN Flag Count": 0,
            "SYN Flag Count": 0,
            "RST Flag Count": 0,
            "PSH Flag Count": 0,
            "ACK Flag Count": 1,
            "URG Flag Count": 0,
            "ECE Flag Count": 0,
            "Down/Up Ratio": 0.0,
            "Average Packet Size": 80.0,
            "Avg Fwd Segment Size": 80.0,
            "Avg Bwd Segment Size": 0.0,
            "Subflow Fwd Packets": 400,
            "Subflow Fwd Bytes": 32000,
            "Subflow Bwd Packets": 0,
            "Subflow Bwd Bytes": 0,
            "Init_Win_bytes_forward": 512,
            "Init_Win_bytes_backward": -1,
            "act_data_pkt_fwd": 400,
            "min_seg_size_forward": 20,
            "Active Mean": 0.0,
            "Active Std": 0.0,
            "Active Max": 0.0,
            "Active Min": 0.0,
            "Idle Mean": 0.0,
            "Idle Std": 0.0,
            "Idle Max": 0.0,
            "Idle Min": 0.0
        }
        return NetworkFlowAnalyzeRequest(
            source_ip=src,
            destination_ip="192.168.1.10",
            source_port=30000 + seq_num,
            destination_port=80,
            protocol="TCP",
            features=features
        )

    elif scenario == "BRUTE_FORCE":
        # Repeated truncated connection to SSH port 22
        features = {
            "Destination Port": 22,
            "Flow Duration": 45000,            # 45ms
            "Total Fwd Packets": 4,
            "Total Backward Packets": 2,
            "Total Length of Fwd Packets": 120,
            "Total Length of Bwd Packets": 80,
            "Fwd Packet Length Max": 60,
            "Fwd Packet Length Min": 20,
            "Fwd Packet Length Mean": 30.0,
            "Fwd Packet Length Std": 17.3,
            "Bwd Packet Length Max": 40,
            "Bwd Packet Length Min": 40,
            "Bwd Packet Length Mean": 40.0,
            "Bwd Packet Length Std": 0.0,
            "Flow Bytes/s": 4444.4,
            "Flow Packets/s": 133.3,
            "Flow IAT Mean": 9000.0,
            "Flow IAT Std": 4000.0,
            "Flow IAT Max": 18000.0,
            "Flow IAT Min": 100.0,
            "Fwd IAT Total": 40000.0,
            "Fwd IAT Mean": 13333.3,
            "Fwd IAT Std": 5000.0,
            "Fwd IAT Max": 20000.0,
            "Fwd IAT Min": 200.0,
            "Bwd IAT Total": 25000.0,
            "Bwd IAT Mean": 25000.0,
            "Bwd IAT Std": 0.0,
            "Bwd IAT Max": 25000.0,
            "Bwd IAT Min": 25000.0,
            "Fwd PSH Flags": 0,
            "Fwd Header Length": 80,
            "Bwd Header Length": 40,
            "Fwd Packets/s": 88.9,
            "Bwd Packets/s": 44.4,
            "Min Packet Length": 20,
            "Max Packet Length": 60,
            "Packet Length Mean": 33.3,
            "Packet Length Std": 15.1,
            "Packet Length Variance": 226.7,
            "FIN Flag Count": 1,
            "SYN Flag Count": 1,
            "RST Flag Count": 1,               # Teardown RST
            "PSH Flag Count": 0,
            "ACK Flag Count": 1,
            "URG Flag Count": 0,
            "ECE Flag Count": 0,
            "Down/Up Ratio": 0.5,
            "Average Packet Size": 33.3,
            "Avg Fwd Segment Size": 30.0,
            "Avg Bwd Segment Size": 40.0,
            "Subflow Fwd Packets": 4,
            "Subflow Fwd Bytes": 120,
            "Subflow Bwd Packets": 2,
            "Subflow Bwd Bytes": 80,
            "Init_Win_bytes_forward": 14600,
            "Init_Win_bytes_backward": 14480,
            "act_data_pkt_fwd": 2,
            "min_seg_size_forward": 20,
            "Active Mean": 0.0,
            "Active Std": 0.0,
            "Active Max": 0.0,
            "Active Min": 0.0,
            "Idle Mean": 0.0,
            "Idle Std": 0.0,
            "Idle Max": 0.0,
            "Idle Min": 0.0
        }
        return NetworkFlowAnalyzeRequest(
            source_ip="203.0.113.88",
            destination_ip="192.168.1.200",
            source_port=49500 + seq_num,
            destination_port=22,
            protocol="TCP",
            features=features
        )
    else:
        raise ValueError(f"Unknown scenario: {scenario}")


def run_simulation(api_url: str = None):
    print("=" * 80)
    print("CIPHER NETWORK INTRUSION DETECTION & IPS - SAFE EVENT SIMULATOR")
    print("=" * 80)
    print("NOTE: Generates synthetic flow records only. ZERO real malicious packets sent.")
    print("Default Mode: DETECT_ONLY (Host Windows Defender and Firewall are NOT modified)")
    print("-" * 80)

    service = NetworkService() if not api_url else None
    scenarios = ["NORMAL", "PORT_SCAN", "DOS", "DDOS", "BRUTE_FORCE"]

    results = []

    for sc in scenarios:
        print(f"\n>>> Running Scenario: [{sc}]")
        req = generate_synthetic_flow(sc, seq_num=1)

        if service:
            res = service.analyze_flow(req)
        else:
            import urllib.request
            req_data = json.dumps(req.dict()).encode("utf-8")
            url_req = urllib.request.Request(
                api_url,
                data=req_data,
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(url_req) as response:
                res_data = json.loads(response.read().decode("utf-8"))
                from app.network.schemas import NetworkDetectionResponse
                res = NetworkDetectionResponse(**res_data)

        results.append((sc, res))

        print(f"  Source -> Dest:     {res.source_ip} -> {res.destination_ip}:{res.destination_port} ({res.protocol})")
        print(f"  Classification:     {res.classification} ({res.attack_type})")
        print(f"  ML Attack Prob:     {res.ml_attack_prob * 100:.2f}% | ML Confidence: {res.ml_confidence * 100:.2f}%")
        print(f"  Threat Score:       {res.threat_score}/100 [{res.severity}]")
        print(f"  Detection Method:   {res.detection_method}")
        print(f"  Recommended Action: {res.recommended_action}")
        print(f"  Applied Response:   {res.applied_action} (Mode: {res.prevention_mode})")
        print(f"  Explanation:        {res.explanation}")

    print("\n" + "=" * 80)
    print("SIMULATION SUMMARY TABLE")
    print("=" * 80)
    print(f"{'Scenario':<14} | {'Attack Type':<12} | {'Threat':<7} | {'Severity':<9} | {'Action':<16} | {'Status':<14}")
    print("-" * 80)
    for sc, res in results:
        print(f"{sc:<14} | {res.attack_type:<12} | {res.threat_score:<7} | {res.severity:<9} | {res.recommended_action:<16} | {res.applied_action:<14}")
    print("=" * 80)
    print("Simulation completed successfully. Verify records in GET /api/network/events or cipher.db.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CIPHER Safe Network Flow Event Simulator")
    parser.add_argument("--api-url", type=str, default=None, help="URL of running CIPHER API (e.g. http://127.0.0.1:8000/api/network/analyze)")
    args = parser.parse_args()
    run_simulation(args.api_url)
