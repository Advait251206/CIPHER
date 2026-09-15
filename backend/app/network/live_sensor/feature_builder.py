"""
CIPHER Live Feature Builder
Translates BidirectionalFlow packet statistics into the exact 67 numerical features
expected by the trained CIC-IDS2017 Network IDS models.
"""

from typing import Dict, Any, List, Tuple
import numpy as np

from app.network.live_sensor.flow import BidirectionalFlow


# Exact feature sequence contract matching network_model_metadata.json
EXPECTED_67_FEATURES = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "ECE Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min"
]


class LiveFeatureBuilder:
    """Computes exact 67 CIC-IDS2017 features from real packet flow measurements."""

    @staticmethod
    def _compute_iat(timestamps: List[float]) -> Tuple[float, float, float, float, float]:
        """Calculates (total, mean, std, max, min) in microseconds from a list of epoch timestamps."""
        if len(timestamps) < 2:
            return 0.0, 0.0, 0.0, 0.0, 0.0
        # Time differences converted to microseconds
        diffs = np.diff(timestamps) * 1e6
        total = float(np.sum(diffs))
        mean = float(np.mean(diffs))
        std = float(np.std(diffs)) if len(diffs) > 1 else 0.0
        max_v = float(np.max(diffs))
        min_v = float(np.min(diffs))
        return total, mean, std, max_v, min_v

    @classmethod
    def build_features(cls, flow: BidirectionalFlow) -> Tuple[Dict[str, float], float]:
        """
        Converts flow state into the 67 CIC-IDS2017 features.

        Returns:
            features (Dict[str, float]): Dictionary with all 67 features
            feature_completeness (float): Metric from 0.0 to 1.0 indicating data availability
        """
        duration_sec = flow.duration_seconds
        # Duration in microseconds (minimum 1.0 µs to prevent zero division)
        duration_us = max(1.0, duration_sec * 1e6)

        all_packet_lengths = flow.fwd_packet_lengths + flow.bwd_packet_lengths
        total_packets = flow.total_packets
        total_fwd_bytes = float(sum(flow.fwd_packet_lengths))
        total_bwd_bytes = float(sum(flow.bwd_packet_lengths))
        total_bytes = total_fwd_bytes + total_bwd_bytes

        # Forward Packet Length Stats
        if flow.fwd_packet_lengths:
            fwd_len_max = float(max(flow.fwd_packet_lengths))
            fwd_len_min = float(min(flow.fwd_packet_lengths))
            fwd_len_mean = float(np.mean(flow.fwd_packet_lengths))
            fwd_len_std = float(np.std(flow.fwd_packet_lengths)) if len(flow.fwd_packet_lengths) > 1 else 0.0
        else:
            fwd_len_max, fwd_len_min, fwd_len_mean, fwd_len_std = 0.0, 0.0, 0.0, 0.0

        # Backward Packet Length Stats
        if flow.bwd_packet_lengths:
            bwd_len_max = float(max(flow.bwd_packet_lengths))
            bwd_len_min = float(min(flow.bwd_packet_lengths))
            bwd_len_mean = float(np.mean(flow.bwd_packet_lengths))
            bwd_len_std = float(np.std(flow.bwd_packet_lengths)) if len(flow.bwd_packet_lengths) > 1 else 0.0
        else:
            bwd_len_max, bwd_len_min, bwd_len_mean, bwd_len_std = 0.0, 0.0, 0.0, 0.0

        # Rates (per second)
        div_duration = duration_sec if duration_sec > 1e-6 else 1e-6
        flow_bytes_per_s = total_bytes / div_duration
        flow_pkts_per_s = float(total_packets) / div_duration
        fwd_pkts_per_s = float(flow.fwd_packet_count) / div_duration
        bwd_pkts_per_s = float(flow.bwd_packet_count) / div_duration

        # Inter-Arrival Times (in microseconds)
        _, flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min = cls._compute_iat(flow.flow_timestamps)
        fwd_iat_total, fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min = cls._compute_iat(flow.fwd_timestamps)
        bwd_iat_total, bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min = cls._compute_iat(flow.bwd_timestamps)

        # Global Packet Length Stats
        if all_packet_lengths:
            pkt_len_min = float(min(all_packet_lengths))
            pkt_len_max = float(max(all_packet_lengths))
            pkt_len_mean = float(np.mean(all_packet_lengths))
            pkt_len_std = float(np.std(all_packet_lengths)) if len(all_packet_lengths) > 1 else 0.0
            pkt_len_var = float(np.var(all_packet_lengths)) if len(all_packet_lengths) > 1 else 0.0
        else:
            pkt_len_min, pkt_len_max, pkt_len_mean, pkt_len_std, pkt_len_var = 0.0, 0.0, 0.0, 0.0, 0.0

        # Down/Up Ratio and Average Packet Size
        down_up_ratio = float(flow.bwd_packet_count) / float(flow.fwd_packet_count) if flow.fwd_packet_count > 0 else 0.0
        avg_packet_size = total_bytes / float(total_packets) if total_packets > 0 else 0.0

        # Active & Idle Statistics (in microseconds)
        if flow.active_durations:
            active_mean = float(np.mean(flow.active_durations) * 1e6)
            active_std = float(np.std(flow.active_durations) * 1e6) if len(flow.active_durations) > 1 else 0.0
            active_max = float(np.max(flow.active_durations) * 1e6)
            active_min = float(np.min(flow.active_durations) * 1e6)
        else:
            active_mean, active_std, active_max, active_min = 0.0, 0.0, 0.0, 0.0

        if flow.idle_durations:
            idle_mean = float(np.mean(flow.idle_durations) * 1e6)
            idle_std = float(np.std(flow.idle_durations) * 1e6) if len(flow.idle_durations) > 1 else 0.0
            idle_max = float(np.max(flow.idle_durations) * 1e6)
            idle_min = float(np.min(flow.idle_durations) * 1e6)
        else:
            idle_mean, idle_std, idle_max, idle_min = 0.0, 0.0, 0.0, 0.0

        # Feature completeness scoring
        # If flow had both fwd and bwd packets, completeness is 1.0; if unidirectional, 0.85
        completeness = 1.0 if (flow.fwd_packet_count > 0 and flow.bwd_packet_count > 0) else 0.85

        features: Dict[str, float] = {
            "Destination Port": float(flow.dst_port),
            "Flow Duration": duration_us,
            "Total Fwd Packets": float(flow.fwd_packet_count),
            "Total Backward Packets": float(flow.bwd_packet_count),
            "Total Length of Fwd Packets": total_fwd_bytes,
            "Total Length of Bwd Packets": total_bwd_bytes,
            "Fwd Packet Length Max": fwd_len_max,
            "Fwd Packet Length Min": fwd_len_min,
            "Fwd Packet Length Mean": fwd_len_mean,
            "Fwd Packet Length Std": fwd_len_std,
            "Bwd Packet Length Max": bwd_len_max,
            "Bwd Packet Length Min": bwd_len_min,
            "Bwd Packet Length Mean": bwd_len_mean,
            "Bwd Packet Length Std": bwd_len_std,
            "Flow Bytes/s": flow_bytes_per_s,
            "Flow Packets/s": flow_pkts_per_s,
            "Flow IAT Mean": flow_iat_mean,
            "Flow IAT Std": flow_iat_std,
            "Flow IAT Max": flow_iat_max,
            "Flow IAT Min": flow_iat_min,
            "Fwd IAT Total": fwd_iat_total,
            "Fwd IAT Mean": fwd_iat_mean,
            "Fwd IAT Std": fwd_iat_std,
            "Fwd IAT Max": fwd_iat_max,
            "Fwd IAT Min": fwd_iat_min,
            "Bwd IAT Total": bwd_iat_total,
            "Bwd IAT Mean": bwd_iat_mean,
            "Bwd IAT Std": bwd_iat_std,
            "Bwd IAT Max": bwd_iat_max,
            "Bwd IAT Min": bwd_iat_min,
            "Fwd PSH Flags": float(flow.fwd_psh_count),
            "Fwd Header Length": float(sum(flow.fwd_header_lengths)),
            "Bwd Header Length": float(sum(flow.bwd_header_lengths)),
            "Fwd Packets/s": fwd_pkts_per_s,
            "Bwd Packets/s": bwd_pkts_per_s,
            "Min Packet Length": pkt_len_min,
            "Max Packet Length": pkt_len_max,
            "Packet Length Mean": pkt_len_mean,
            "Packet Length Std": pkt_len_std,
            "Packet Length Variance": pkt_len_var,
            "FIN Flag Count": float(flow.fin_count),
            "SYN Flag Count": float(flow.syn_count),
            "RST Flag Count": float(flow.rst_count),
            "PSH Flag Count": float(flow.psh_count),
            "ACK Flag Count": float(flow.ack_count),
            "URG Flag Count": float(flow.urg_count),
            "ECE Flag Count": float(flow.ece_count),
            "Down/Up Ratio": down_up_ratio,
            "Average Packet Size": avg_packet_size,
            "Avg Fwd Segment Size": fwd_len_mean,
            "Avg Bwd Segment Size": bwd_len_mean,
            "Subflow Fwd Packets": float(flow.fwd_packet_count),
            "Subflow Fwd Bytes": total_fwd_bytes,
            "Subflow Bwd Packets": float(flow.bwd_packet_count),
            "Subflow Bwd Bytes": total_bwd_bytes,
            "Init_Win_bytes_forward": float(flow.init_win_bytes_fwd),
            "Init_Win_bytes_backward": float(flow.init_win_bytes_bwd),
            "act_data_pkt_fwd": float(flow.act_data_pkt_fwd),
            "min_seg_size_forward": float(flow.min_seg_size_fwd),
            "Active Mean": active_mean,
            "Active Std": active_std,
            "Active Max": active_max,
            "Active Min": active_min,
            "Idle Mean": idle_mean,
            "Idle Std": idle_std,
            "Idle Max": idle_max,
            "Idle Min": idle_min
        }

        # Sanitize any unexpected NaN or Inf
        for k, v in features.items():
            if np.isnan(v):
                features[k] = 0.0
            elif np.isposinf(v):
                features[k] = 1e6
            elif np.isneginf(v):
                features[k] = 0.0

        return features, completeness
