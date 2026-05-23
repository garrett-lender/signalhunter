#!/usr/bin/env python3
"""
Benign SYN-scan-like local trigger.

Rapidly attempts TCP connections against localhost ports.
This is local-only and intentionally small.
"""

import socket
import time
import os

HOST = "127.0.0.1"
START_PORT = 35000
COUNT = 80
TIMEOUT = 0.03

print(f"[test] pid={os.getpid()} rapidly connecting to {HOST}:{START_PORT}-{START_PORT + COUNT - 1}")

for port in range(START_PORT, START_PORT + COUNT):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT)
    try:
        s.connect((HOST, port))
    except OSError:
        pass
    finally:
        s.close()

print("[test] done")
time.sleep(5)
