#!/usr/bin/env python3
"""
Reliable SignalHunter beacon/heartbeat trigger.

This is benign and localhost-only.  It creates a local server, then a client that:
  1. connects to 127.0.0.1
  2. sends heartbeat messages for a few seconds
  3. server closes the connection
  4. client waits a fixed interval and reconnects

This gives SignalHunter two chances to detect beaconing:
  - eBPF connect() events see each reconnect immediately
  - /proc polling sees each connection because it stays ESTABLISHED for several seconds
"""

import argparse
import os
import socket
import threading
import time

HOST = "127.0.0.1"
DEFAULT_PORT = 45555


def server(host: str, port: int, hold_seconds: float) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(16)
        print(f"[server] listening on {host}:{port}")

        while True:
            conn, addr = srv.accept()
            print(f"[server] accepted {addr}; holding for {hold_seconds:.1f}s")
            deadline = time.time() + hold_seconds
            with conn:
                conn.settimeout(0.5)
                while time.time() < deadline:
                    try:
                        data = conn.recv(1024)
                        if not data:
                            break
                        conn.sendall(b"ack\n")
                    except socket.timeout:
                        pass
                    except OSError:
                        break
            print("[server] dropped connection")


def client(host: str, port: int, interval: float, cycles: int, heartbeat_gap: float) -> None:
    print(f"[client] pid={os.getpid()} reconnecting every ~{interval:.1f}s for {cycles} cycles")

    for i in range(cycles):
        try:
            print(f"[client] cycle {i + 1}/{cycles}: connect")
            with socket.create_connection((host, port), timeout=2) as s:
                s.settimeout(1)
                start = time.time()
                while time.time() - start < max(1.0, interval / 2.0):
                    s.sendall(b"heartbeat\n")
                    try:
                        s.recv(32)
                    except socket.timeout:
                        pass
                    time.sleep(heartbeat_gap)
        except OSError as e:
            print(f"[client] connection failed: {e}")

        print(f"[client] sleeping {interval:.1f}s before reconnect")
        time.sleep(interval)

    print("[client] complete; sleeping briefly for triage")
    time.sleep(10)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--interval", type=float, default=5.0)
    parser.add_argument("--cycles", type=int, default=12)
    parser.add_argument("--hold", type=float, default=4.0)
    parser.add_argument("--heartbeat-gap", type=float, default=1.0)
    args = parser.parse_args()

    t = threading.Thread(target=server, args=(args.host, args.port, args.hold), daemon=True)
    t.start()
    time.sleep(0.5)
    client(args.host, args.port, args.interval, args.cycles, args.heartbeat_gap)


if __name__ == "__main__":
    main()
