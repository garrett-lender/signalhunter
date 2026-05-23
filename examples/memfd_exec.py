#!/usr/bin/env python3
"""
Benign memfd trigger.

Creates an anonymous memfd and maps it executable.
This should trigger memfd/executable mapping heuristics on many kernels.

No payload is executed.
"""

import mmap
import os
import time

print(f"[test] pid={os.getpid()} creating memfd")

if not hasattr(os, "memfd_create"):
    print("[test] os.memfd_create is unavailable on this Python/kernel")
    raise SystemExit(1)

fd = os.memfd_create("signalhunter_test_memfd", flags=0)
os.write(fd, b"SIGNALHUNTER_TEST_MEMFD" + b"\x00" * 4096)
os.lseek(fd, 0, os.SEEK_SET)

m = mmap.mmap(
    fd,
    4096,
    prot=mmap.PROT_READ | mmap.PROT_EXEC,
    flags=mmap.MAP_PRIVATE,
)

print("[test] executable memfd mapping created; sleeping")
time.sleep(60)
m.close()
os.close(fd)
