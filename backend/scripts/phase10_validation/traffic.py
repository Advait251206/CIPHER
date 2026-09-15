"""
CIPHER Phase 10 Safe Localhost Traffic Generator.
Strictly generates bounded, harmless network traffic on localhost (127.0.0.1 / loopback).
NEVER connects to external IPs, corporate subnets, or public hosts.
"""

import time
import socket
import threading
import logging
from typing import List, Tuple
from http.server import HTTPServer, BaseHTTPRequestHandler
from .config import (
    DEFAULT_TEST_TARGET,
    assert_safe_target,
    validate_traffic_bounds,
    DEFAULT_TIMEOUT_SECONDS,
)

logger = logging.getLogger("cipher.phase10.traffic")


class MinimalEchoHandler(BaseHTTPRequestHandler):
    """Responds with 200 OK for benign HTTP validation flows."""

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", "18")
        self.end_headers()
        self.wfile.write(b"CIPHER-VALIDATION")

    def log_message(self, format, *args):
        # Silence standard HTTP access logging to preserve clean console output
        pass


class LocalTestServer:
    """Threaded local loopback test server providing genuine TCP/HTTP endpoints."""

    def __init__(self, host: str = DEFAULT_TEST_TARGET, port: int = 18080):
        assert_safe_target(host)
        self.host = host
        self.port = port
        self.server: HTTPServer = None
        self.thread: threading.Thread = None
        self.stop_event = threading.Event()

    def start(self) -> None:
        self.stop_event.clear()
        self.server = HTTPServer((self.host, self.port), MinimalEchoHandler)
        self.server.timeout = 0.5
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        time.sleep(0.2)  # Allow socket to bind
        logger.info(f"Local test server listening on http://{self.host}:{self.port}")

    def _run(self) -> None:
        while not self.stop_event.is_set():
            if self.server:
                self.server.handle_request()

    def stop(self) -> None:
        self.stop_event.set()
        if self.server:
            try:
                self.server.server_close()
            except Exception:
                pass
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=1.0)
        logger.info("Local test server stopped.")


def send_benign_http_requests(
    host: str = DEFAULT_TEST_TARGET,
    port: int = 18080,
    count: int = 5
) -> int:
    """
    Sends bounded standard HTTP GET requests to the local test server.
    """
    assert_safe_target(host)
    validate_traffic_bounds(count, count * 1.0)

    successful = 0
    for i in range(count):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(DEFAULT_TIMEOUT_SECONDS)
                s.connect((host, port))
                req = f"GET /benign-{i} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
                s.sendall(req.encode())
                resp = s.recv(512)
                if resp:
                    successful += 1
        except Exception as e:
            logger.debug(f"Benign request #{i} error: {e}")
        time.sleep(0.05)
    return successful


def send_local_port_sweep(
    host: str = DEFAULT_TEST_TARGET,
    ports: List[int] = None
) -> List[Tuple[int, bool]]:
    """
    Generates bounded connection probes to specified local ports on loopback.
    Returns list of (port, connected_boolean).
    """
    assert_safe_target(host)
    if ports is None:
        ports = list(range(18010, 18022))  # 12 bounded local ports

    validate_traffic_bounds(len(ports), len(ports) * 0.5)

    results = []
    for p in ports:
        connected = False
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.15)
                s.connect((host, p))
                connected = True
        except (ConnectionRefusedError, socket.timeout, OSError):
            connected = False
        results.append((p, connected))
        time.sleep(0.05)

    return results


def send_local_auth_burst(
    host: str = DEFAULT_TEST_TARGET,
    port: int = 22,
    count: int = 6
) -> int:
    """
    Sends bounded connection attempts targeting an authentication port on loopback.
    Does NOT send credentials or attack real accounts.
    """
    assert_safe_target(host)
    validate_traffic_bounds(count, count * 0.5)

    attempts = 0
    for _ in range(count):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.15)
                s.connect((host, port))
        except (ConnectionRefusedError, socket.timeout, OSError):
            pass
        attempts += 1
        time.sleep(0.05)

    return attempts
