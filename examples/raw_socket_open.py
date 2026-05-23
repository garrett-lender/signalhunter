#!/usr/bin/env python3
"""
Benign raw socket trigger.

Opens a raw socket and immediately sleeps.
Requires root/CAP_NET_RAW.

This does not send packets.
"""

import os
import socket
import time

print(f"[test] pid={os.getpid()} opening raw socket")

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
except PermissionError:
    print("[test] permission denied; rerun with sudo")
    raise SystemExit(1)

print("[test] raw socket opened; no packets will be sent")
time.sleep(30)
s.close()
