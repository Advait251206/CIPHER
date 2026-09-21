"""
CIPHER Live Packet Capture
Manages low-overhead live packet sniffing via Scapy and Npcap on Windows/Linux,
safely validating BPF filters and dispatching packets to the flow aggregator.
"""

import time
import logging
from typing import Callable, Optional, Any, Dict, List

logger = logging.getLogger("cipher.network.packet_capture")

try:
    from scapy.all import AsyncSniffer, conf
    from scapy.arch.common import compile_filter
    from scapy.error import Scapy_Exception
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    AsyncSniffer = None
    conf = None
    compile_filter = None
    Scapy_Exception = Exception


def is_npcap_available() -> bool:
    """Checks whether Scapy has access to Npcap/WinPcap packet capture driver."""
    if not SCAPY_AVAILABLE or conf is None:
        return False
    return getattr(conf, "use_pcap", False) is True


def get_available_interfaces() -> List[Dict[str, Any]]:
    """
    Enumerates host network interfaces available for packet capture.
    Returns sanitized, human-readable interface descriptors.
    """
    if not SCAPY_AVAILABLE:
        return []

    results: List[Dict[str, Any]] = []
    seen_names = set()

    # Query scapy conf.ifaces
    try:
        for iface_id, iface in conf.ifaces.items():
            name = getattr(iface, "name", str(iface_id))
            if name in seen_names:
                continue
            seen_names.add(name)

            desc = getattr(iface, "description", "") or getattr(iface, "network_name", "")
            guid = getattr(iface, "guid", "")
            ip_str = ""
            raw_ip = getattr(iface, "ip", None)
            if isinstance(raw_ip, str) and raw_ip.strip():
                ip_str = raw_ip.strip()
            else:
                raw_ips = getattr(iface, "ips", [])
                if isinstance(raw_ips, (list, tuple)):
                    for item in raw_ips:
                        if isinstance(item, str) and item.strip():
                            ip_str = item.strip()
                            break

            # Check if valid for capture
            status = "available" if getattr(iface, "is_valid", True) else "disabled"

            results.append({
                "name": name,
                "description": desc,
                "address": ip_str,
                "guid": guid,
                "status": status
            })
    except Exception as e:
        logger.error(f"[PACKET_CAPTURE] Error querying interfaces: {e}")

    return results


def resolve_interface(name_or_guid_or_desc: str) -> Any:
    """
    Resolves a human-friendly name, GUID, description, or IP to a valid Scapy interface.
    Raises ValueError if interface cannot be found.
    """
    if not SCAPY_AVAILABLE:
        raise RuntimeError("Scapy is not installed. Live packet capture is unavailable.")

    if not name_or_guid_or_desc:
        raise ValueError("No interface specified.")

    target = name_or_guid_or_desc.strip()

    # 1. Direct lookup via dev_from_name
    try:
        dev = conf.ifaces.dev_from_name(target)
        if dev:
            return dev
    except Exception:
        pass

    # 2. Iterate over all interfaces and match by name, description, guid, or IP
    for iface in conf.ifaces.values():
        if getattr(iface, "name", None) == target:
            return iface
        if getattr(iface, "description", None) == target:
            return iface
        if getattr(iface, "guid", None) == target:
            return iface
        if getattr(iface, "network_name", None) == target:
            return iface
        if getattr(iface, "ip", None) == target:
            return iface
        if target in getattr(iface, "ips", []):
            return iface

    raise ValueError(
        f"Interface '{target}' was not found. "
        f"Use GET /api/network/interfaces to view active network adapters."
    )


def validate_bpf_filter(filter_str: Optional[str], iface: Any = None) -> None:
    """
    Validates a Berkeley Packet Filter (BPF) syntax using Scapy compile_filter.
    Raises ValueError on invalid syntax.
    """
    if not filter_str or not filter_str.strip():
        return  # Empty filter is valid (matches all packets)

    if not SCAPY_AVAILABLE or compile_filter is None:
        raise RuntimeError("Scapy compile_filter unavailable to validate BPF syntax.")

    try:
        # linktype=1 corresponds to Ethernet (DLT_EN10MB)
        compile_filter(filter_str.strip(), iface=iface, linktype=1)
    except Scapy_Exception as e:
        raise ValueError(f"Invalid BPF filter expression '{filter_str}': {e}")
    except Exception as e:
        raise ValueError(f"Failed to compile BPF filter '{filter_str}': {e}")


import json
import subprocess
import threading
import os

class PacketCapture:
    """
    Controls live packet sniffing lifecycle in a non-blocking background thread.
    Zero payload persistence: packet callbacks immediately extract flow metadata.
    Uses the highly optimized C++ Npcap sensor executable.
    """

    def __init__(
        self,
        on_packet: Callable[[Any], None],
        interface: Optional[str] = None,
        bpf_filter: Optional[str] = None,
        on_arp: Optional[Callable[[Any], None]] = None
    ):
        self.on_packet = on_packet
        self.on_arp = on_arp
        self.interface_name = interface
        self.bpf_filter = bpf_filter

        self._resolved_iface = None
        self._process: Optional[subprocess.Popen] = None
        self._reader_thread: Optional[threading.Thread] = None
        self._is_running = False
        self.packets_captured = 0
        self.errors = 0
        self.start_time: Optional[float] = None

    @property
    def is_running(self) -> bool:
        return self._is_running and (self._process is not None and self._process.poll() is None)

    def start(self):
        """Validates settings and starts the Scapy AsyncSniffer background thread."""
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is not installed. Live packet capture cannot start.")

        if not is_npcap_available():
            raise RuntimeError(
                "Npcap is not installed or not operational. "
                "Please install Npcap with 'WinPcap API-compatible mode' enabled."
            )

        if self.is_running:
            logger.warning("[PACKET_CAPTURE] Sniffer is already running.")
            return

        if not self.interface_name:
            raise ValueError("No interface specified for packet capture.")

        # Resolve interface
        self._resolved_iface = resolve_interface(self.interface_name)

        # Validate BPF filter
        if self.bpf_filter:
            validate_bpf_filter(self.bpf_filter, self._resolved_iface)

        logger.info(
            f"[SENSOR] Starting C++ capture on interface '{getattr(self._resolved_iface, 'name', self.interface_name)}' "
        )

        sensor_exe = os.path.join(os.path.dirname(__file__), "..", "..", "..", "cpp_sensor", "sensor.exe")
        target_iface = getattr(self._resolved_iface, "network_name", getattr(self._resolved_iface, "name", self.interface_name))

        try:
            self._process = subprocess.Popen(
                [sensor_exe, target_iface],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )
            
            self._is_running = True
            self.start_time = time.time()
            self.packets_captured = 0
            self.errors = 0
            
            self._reader_thread = threading.Thread(target=self._read_stdout_loop, daemon=True)
            self._reader_thread.start()
            
        except Exception as e:
            self._is_running = False
            self._process = None
            logger.error(f"[PACKET_CAPTURE] Failed to start C++ sniffer: {e}")
            raise RuntimeError(f"Failed to start C++ packet capture: {e}")

    def _read_stdout_loop(self):
        """Reads JSON lines from the C++ sensor process."""
        if not self._process or not self._process.stdout:
            return
            
        while self._is_running and self._process.poll() is None:
            line = self._process.stdout.readline()
            if not line:
                break
                
            line = line.strip()
            if not line:
                continue
                
            if line.startswith("{"):
                try:
                    parsed = json.loads(line)
                    self._on_packet_wrapper(parsed)
                except Exception as e:
                    self.errors += 1
                    logger.debug(f"[PACKET_CAPTURE] JSON parse error: {e}")
            else:
                logger.info(f"[CPP_SENSOR] {line}")

    def _on_packet_wrapper(self, pkt: Any):
        """Non-blocking internal wrapper tracking packet count and handling exceptions."""
        try:
            self.packets_captured += 1
            if pkt.get("type") == "arp":
                if self.on_arp:
                    self.on_arp(pkt)
            else:
                self.on_packet(pkt)
        except Exception as e:
            self.errors += 1
            logger.debug(f"[PACKET_CAPTURE] Packet processing callback error: {e}")

    def stop(self):
        """Gracefully stops the C++ sensor process."""
        if not self._is_running or self._process is None:
            self._is_running = False
            return

        logger.info("[SENSOR] Stopping C++ packet capture...")
        self._is_running = False
        
        try:
            self._process.terminate()
            self._process.wait(timeout=2.0)
        except Exception as e:
            logger.warning(f"[PACKET_CAPTURE] Warning while stopping sniffer: {e}")
            try:
                self._process.kill()
            except:
                pass
        finally:
            self._process = None
            logger.info(f"[SENSOR] Stopped. Captured {self.packets_captured} packets.")
