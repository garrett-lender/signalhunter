#!/usr/bin/env python3
"""
Benign RWX mmap trigger.

Allocates anonymous memory with read/write/execute permissions.
This does not execute shellcode; it only creates the suspicious memory mapping.
"""

import mmap
import os
import time

PAGE = 4096

print(f"[test] pid={os.getpid()} creating RWX anonymous mmap")
m = mmap.mmap(
    -1,
    PAGE,
    prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC,
)
m.write(b"SIGNALHUNTER_TEST_RWX\x00")

print("[test] RWX mmap created; sleeping so SignalHunter can scan /proc/<pid>/maps")
time.sleep(60)
