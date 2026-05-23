#!/usr/bin/env python3
"""
Benign localhost beacon simulator.

Creates a local TCP server and repeatedly connects to it at a stable interval.
SignalHunter should eventually flag this as beacon-like timing.
"""

import socket
import threading
import time

HOST = "127.0.0.1"
PORT = 44444
INTERVAL_SECONDS = 5
COUNT = 20


def server() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, PORT))
        srv.listen(16)

        while True:
            conn, _addr = srv.accept()
            with conn:
                conn.recv(1024)
                conn.sendall(b"ok\n")


def main() -> None:
    t = threading.Thread(target=server, daemon=True)
    t.start()
    time.sleep(0.5)

    print(f"[test] beaconing to {HOST}:{PORT} every {INTERVAL_SECONDS}s")

    for i in range(COUNT):
        with socket.create_connection((HOST, PORT), timeout=2) as s:
            s.sendall(b"ping\n")
            s.recv(32)

        print(f"[test] beacon {i + 1}/{COUNT}")
        time.sleep(INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
