#!/usr/bin/env python3
"""
Reliable local beacon trigger for SignalHunter.

This uses repeated localhost connects. With an eBPF build, every connect()
is observed, so this is much more reliable than trying to catch very short
connections via /proc polling.
"""
import socket
import threading
import time
import os

HOST = "127.0.0.1"
PORT = 45555
INTERVAL = 3
COUNT = 12


def server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, PORT))
        srv.listen(32)
        while True:
            conn, _ = srv.accept()
            with conn:
                conn.recv(1024)
                conn.sendall(b"ok\n")


def main():
    print(f"[test] pid={os.getpid()} reliable beacon to {HOST}:{PORT}")
    threading.Thread(target=server, daemon=True).start()
    time.sleep(0.5)
    for i in range(COUNT):
        with socket.create_connection((HOST, PORT), timeout=2) as s:
            s.sendall(b"beacon\n")
            s.recv(32)
        print(f"[test] beacon {i + 1}/{COUNT}")
        time.sleep(INTERVAL)
    print("[test] done; sleeping briefly for case collection")
    time.sleep(10)

if __name__ == "__main__":
    main()
