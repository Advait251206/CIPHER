#!/usr/bin/env python3
"""
CIPHER Unified Development Runner
Runs both FastAPI backend (127.0.0.1:8000) and Vite frontend (localhost:3000) concurrently.
Handles clean process termination on Ctrl+C (Windows & POSIX).
"""

import sys
import os
import subprocess
import threading
import signal
import time

CYAN = "\033[96m"
MAGENTA = "\033[95m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"
BOLD = "\033[1m"

# Enable ANSI colors on Windows console
if sys.platform == "win32":
    os.system("")

def stream_output(process, prefix, color):
    try:
        for line in iter(process.stdout.readline, ""):
            if not line:
                break
            print(f"{color}{BOLD}[{prefix}]{RESET} {line.rstrip()}", flush=True)
    except Exception:
        pass

def main():
    root_dir = os.path.dirname(os.path.abspath(__file__))
    backend_dir = os.path.join(root_dir, "backend")
    frontend_dir = os.path.join(root_dir, "frontend")

    print(f"{GREEN}{BOLD}============================================================{RESET}")
    print(f"{GREEN}{BOLD}      CIPHER — Cyber Intrusion Prevention & Response       {RESET}")
    print(f"{GREEN}{BOLD}============================================================{RESET}")
    print(f"{YELLOW}Starting Backend (FastAPI on http://127.0.0.1:8000)...{RESET}")
    print(f"{YELLOW}Starting Frontend (Vite on http://localhost:3000)...{RESET}")
    print(f"{YELLOW}Press Ctrl+C to terminate both servers cleanly.{RESET}\n")

    # Start Backend
    backend_cmd = [
        sys.executable,
        "-m",
        "uvicorn",
        "app.main:app",
        "--app-dir",
        "backend",
        "--host",
        "127.0.0.1",
        "--port",
        "8000",
        "--reload",
    ]
    backend_proc = subprocess.Popen(
        backend_cmd,
        cwd=root_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    t_backend = threading.Thread(
        target=stream_output, args=(backend_proc, "BACKEND", CYAN), daemon=True
    )
    t_backend.start()

    print(f"\n{CYAN}{BOLD}[SYSTEM] Waiting 4 seconds for backend to initialize...{RESET}")
    time.sleep(4)

    # Start Frontend (npm run dev)
    frontend_cmd = ["npm", "run", "dev"]
    if sys.platform == "win32":
        frontend_cmd = ["cmd.exe", "/c", "npm run dev"]

    frontend_proc = subprocess.Popen(
        frontend_cmd,
        cwd=frontend_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    t_frontend = threading.Thread(
        target=stream_output, args=(frontend_proc, "FRONTEND", MAGENTA), daemon=True
    )
    t_frontend.start()

    def shutdown(signum=None, frame=None):
        print(f"\n{RED}{BOLD}[SHUTDOWN] Terminating servers...{RESET}")
        try:
            if sys.platform == "win32":
                subprocess.call(["taskkill", "/F", "/T", "/PID", str(backend_proc.pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.call(["taskkill", "/F", "/T", "/PID", str(frontend_proc.pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                backend_proc.terminate()
                frontend_proc.terminate()
        except Exception:
            pass
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    try:
        while backend_proc.poll() is None and frontend_proc.poll() is None:
            time.sleep(0.5)
    except KeyboardInterrupt:
        shutdown()

    shutdown()

if __name__ == "__main__":
    main()
