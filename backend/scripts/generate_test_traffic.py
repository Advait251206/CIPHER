"""
CIPHER Local Test Traffic Generator
Safely generates controlled, harmless TCP and UDP traffic strictly against a
LOCAL test service running on loopback (127.0.0.1).

STRICT SAFETY CONSTRAINTS:
- NEVER sends traffic to external IPs or third-party hosts.
- Targets ONLY 127.0.0.1 on ephemeral/local ports.
- Used exclusively to verify that packet capture, flow tracking,
  and timeout expiration operate correctly in local development/test environments.
"""

import time
import socket
import threading
import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler

TEST_HOST = "127.0.0.1"
DEFAULT_TEST_PORT = 9876


class HarmlessEchoHandler(BaseHTTPRequestHandler):
    """Simple HTTP request handler that responds with 200 OK."""
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", "14")
        self.end_headers()
        self.wfile.write(b"CIPHER-TEST-OK")

    def log_message(self, format, *args):
        # Suppress noisy HTTP server logs
        pass


def run_local_tcp_server(host: str, port: int, stop_event: threading.Event):
    """Runs a minimal local HTTP server on loopback to provide a genuine TCP responder."""
    server = HTTPServer((host, port), HarmlessEchoHandler)
    server.timeout = 0.5
    while not stop_event.is_set():
        server.handle_request()
    server.server_close()


def run_local_udp_server(host: str, port: int, stop_event: threading.Event):
    """Runs a minimal local UDP echo server on loopback."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    sock.settimeout(0.5)
    while not stop_event.is_set():
        try:
            data, addr = sock.recvfrom(1024)
            sock.sendto(b"PONG:" + data, addr)
        except socket.timeout:
            continue
        except Exception:
            break
    sock.close()


def send_benign_http_requests(count: int = 5, port: int = DEFAULT_TEST_PORT):
    """Generates standard bidirectional HTTP TCP flows against the local server."""
    print(f"[*] Sending {count} benign HTTP requests to http://{TEST_HOST}:{port}...")
    for i in range(count):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2.0)
                s.connect((TEST_HOST, port))
                req = f"GET /test-{i} HTTP/1.1\r\nHost: {TEST_HOST}\r\nConnection: close\r\n\r\n"
                s.sendall(req.encode())
                resp = s.recv(1024)
                print(f"    [TCP #{i+1}] Connected, sent {len(req)} bytes, received {len(resp)} bytes.")
        except Exception as e:
            print(f"    [TCP #{i+1}] Error: {e}")
        time.sleep(0.2)


def send_benign_udp_burst(count: int = 10, port: int = DEFAULT_TEST_PORT + 1):
    """Generates bidirectional UDP datagram flows against the local UDP server."""
    print(f"[*] Sending {count} UDP packets to {TEST_HOST}:{port}...")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(2.0)
            for i in range(count):
                msg = f"CIPHER_PING_{i}".encode()
                s.sendto(msg, (TEST_HOST, port))
                try:
                    resp, _ = s.recvfrom(1024)
                    print(f"    [UDP #{i+1}] Sent {len(msg)} bytes, received echo {len(resp)} bytes.")
                except socket.timeout:
                    print(f"    [UDP #{i+1}] Sent {len(msg)} bytes (no echo timeout).")
                time.sleep(0.1)
    except Exception as e:
        print(f"    [UDP] Error: {e}")


def send_simulated_local_probe(ports_count: int = 5, base_port: int = 9880):
    """
    Simulates a small, harmless local connection probe against unmapped local ports
    to demonstrate half-open / RST heuristic flow classification strictly on loopback.
    """
    print(f"[*] Testing harmless local connection probes on ports {base_port}..{base_port+ports_count-1}...")
    for p in range(base_port, base_port + ports_count):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.2)
            s.connect((TEST_HOST, p))
            s.close()
            print(f"    [Probe {p}] Connected.")
        except ConnectionRefusedError:
            print(f"    [Probe {p}] Port closed (TCP RST received as expected).")
        except Exception as e:
            print(f"    [Probe {p}] Result: {e}")
        time.sleep(0.1)


def main():
    parser = argparse.ArgumentParser(description="CIPHER Harmless Local Test Traffic Generator")
    parser.add_argument("--tcp-requests", type=int, default=5, help="Number of local HTTP TCP flows (default: 5)")
    parser.add_argument("--udp-packets", type=int, default=10, help="Number of local UDP packets (default: 10)")
    parser.add_argument("--probe-ports", type=int, default=5, help="Number of local probe ports to test (default: 5)")
    args = parser.parse_args()

    print("=" * 65)
    print("      CIPHER LOCAL TEST TRAFFIC GENERATOR")
    print(f"  Target: Strictly LOCALHOST ({TEST_HOST}) only")
    print("=" * 65)

    stop_event = threading.Event()

    # Start temporary local HTTP server in background thread
    tcp_server_thread = threading.Thread(
        target=run_local_tcp_server,
        args=(TEST_HOST, DEFAULT_TEST_PORT, stop_event),
        daemon=True
    )
    tcp_server_thread.start()

    # Start temporary local UDP server in background thread
    udp_server_thread = threading.Thread(
        target=run_local_udp_server,
        args=(TEST_HOST, DEFAULT_TEST_PORT + 1, stop_event),
        daemon=True
    )
    udp_server_thread.start()

    time.sleep(0.5)

    try:
        # 1. Benign HTTP TCP traffic
        if args.tcp_requests > 0:
            send_benign_http_requests(args.tcp_requests, DEFAULT_TEST_PORT)

        # 2. Benign UDP traffic
        if args.udp_packets > 0:
            send_benign_udp_burst(args.udp_packets, DEFAULT_TEST_PORT + 1)

        # 3. Simulated local probe
        if args.probe_ports > 0:
            send_simulated_local_probe(args.probe_ports)

        print("\n[+] Local traffic generation complete. All sockets closed.")
    finally:
        stop_event.set()
        time.sleep(0.5)


if __name__ == "__main__":
    main()
