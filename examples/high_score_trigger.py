#!/usr/bin/env python3
"""
High-confidence SignalHunter trigger.

Designed to create a case at --case-threshold 85 by combining benign local-only
signals:
  - raw socket open (requires sudo/CAP_NET_RAW)
  - RWX anonymous mmap
  - executable memfd mapping
  - repeated localhost connect beacon
  - local scan-like connects
  - exec from /tmp

No shellcode is executed. No external network targets are contacted.
"""
import mmap
import os
import socket
import stat
import subprocess
import tempfile
import threading
import time

HOST = "127.0.0.1"
PORT = 45556


def beacon_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, PORT))
        srv.listen(32)
        while True:
            conn, _ = srv.accept()
            with conn:
                conn.recv(1024)
                conn.sendall(b"ok")


def start_beaconing():
    for i in range(12):
        try:
            with socket.create_connection((HOST, PORT), timeout=2) as s:
                s.sendall(b"beacon")
                s.recv(32)
        except OSError:
            pass
        print(f"[test] beacon {i + 1}/12")
        time.sleep(3)


def create_rwx_mapping():
    m = mmap.mmap(-1, 4096, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
    m.write(b"SIGNALHUNTER_TEST_RWX")
    return m


def create_memfd_mapping():
    if not hasattr(os, "memfd_create"):
        print("[test] memfd_create unavailable")
        return None
    fd = os.memfd_create("signalhunter_trigger", flags=0)
    os.write(fd, b"A" * 4096)
    os.lseek(fd, 0, os.SEEK_SET)
    mapping = mmap.mmap(fd, 4096, prot=mmap.PROT_READ | mmap.PROT_EXEC, flags=mmap.MAP_PRIVATE)
    return fd, mapping


def open_raw_socket():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        print("[test] raw socket opened")
        return s
    except PermissionError:
        print("[test] raw socket permission denied; run with sudo for strongest trigger")
        return None


def scan_like_connects():
    for port in range(30000, 30120):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.02)
        try:
            s.connect((HOST, port))
        except OSError:
            pass
        finally:
            s.close()


def exec_from_tmp():
    tmp = tempfile.NamedTemporaryFile(prefix="rw_trigger_", suffix=".sh", dir="/tmp", delete=False)
    tmp.write(b"#!/bin/sh\necho SIGNALHUNTER_TRIGGER\nsleep 15\n")
    tmp.close()
    os.chmod(tmp.name, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    print(f"[test] exec from tmp: {tmp.name}")
    subprocess.Popen([tmp.name])


def main():
    print(f"[test] high-score trigger pid={os.getpid()}")
    threading.Thread(target=beacon_server, daemon=True).start()
    time.sleep(0.5)

    rwx = create_rwx_mapping()
    memfd = create_memfd_mapping()
    rawsock = open_raw_socket()
    exec_from_tmp()
    scan_like_connects()

    t = threading.Thread(target=start_beaconing)
    t.start()

    print("[test] suspicious-but-benign behaviors active; sleeping for SignalHunter")
    time.sleep(75)

    if rawsock:
        rawsock.close()
    if memfd:
        fd, mapping = memfd
        mapping.close()
        os.close(fd)
    rwx.close()


if __name__ == "__main__":
    main()
