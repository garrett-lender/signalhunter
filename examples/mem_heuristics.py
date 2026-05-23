#!/usr/bin/env python3
"""
SignalHunter memory/shellcode heuristic trigger.

This is a benign local test program. It does NOT execute shellcode, connect to
external hosts, or exploit anything.

It creates suspicious-but-controlled memory artifacts so SignalHunter can test:
  - RWX anonymous mapping
  - NOP sled heuristics
  - syscall-pattern heuristics
  - ELF header in suspicious memory
  - PE-like header in suspicious memory
  - executable memfd mapping
  - suspicious strings extraction

Run SignalHunter in another terminal first:

    sudo ./signalhunter --case-threshold 85 --verbose

Then run this:

    python3 test_mem_heuristics.py

For raw socket/syscall scoring too:

    sudo python3 test_mem_heuristics.py --raw-socket
"""

import argparse
import mmap
import os
import platform
import socket
import struct
import time


PAGE = 4096


def make_pe_like_blob() -> bytes:
    blob = bytearray(b"MZ" + b"\x00" * 1022)
    pe_offset = 0x80
    struct.pack_into("<I", blob, 0x3C, pe_offset)
    blob[pe_offset:pe_offset + 4] = b"PE\x00\x00"
    return bytes(blob)


def arch_nop_pattern() -> bytes:
    machine = platform.machine().lower()

    if machine in ("x86_64", "amd64", "i386", "i686"):
        return (b"\x90" * 256) + b"\x0f\x05" + b"\xcd\x80"

    if machine in ("aarch64", "arm64"):
        return (b"\x1f\x20\x03\xd5" * 64) + b"\x01\x00\x00\xd4"

    if machine.startswith("arm"):
        return (b"\x00\x00\xa0\xe1" * 64) + b"\x00\x00\x00\xef"

    if "mips" in machine:
        return (
            (b"\x00\x00\x00\x00" * 64)
            + (b"\x00\x00\x00\x0c" * 4)
            + (b"\x0c\x00\x00\x00" * 4)
        )

    return b"\x90" * 256


def create_rwx_mapping() -> mmap.mmap:
    print("[test] creating RWX anonymous mapping")

    m = mmap.mmap(
        -1,
        PAGE * 4,
        prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC,
    )

    payload = bytearray()
    payload += b"SIGNALHUNTER_TEST_RWX_START\n"
    payload += arch_nop_pattern()
    payload += b"\nhttp://example.invalid/beacon\n"
    payload += b"/bin/sh -c whoami\n"
    payload += b"LD_PRELOAD=/tmp/fake.so\n"
    payload += b"memfd_create suspicious marker\n"
    payload += b"\x7fELF" + b"\x00" * 128
    payload += make_pe_like_blob()
    payload += b"SIGNALHUNTER_TEST_RWX_END\n"

    m.write(bytes(payload[:PAGE * 4]))
    return m


def create_exec_memfd_mapping():
    if not hasattr(os, "memfd_create"):
        print("[test] memfd_create unavailable on this Python/kernel")
        return None

    print("[test] creating executable memfd mapping")

    fd = os.memfd_create("signalhunter_memscan_test", flags=0)

    blob = bytearray()
    blob += b"\x7fELF"
    blob += b"\x00" * 256
    blob += arch_nop_pattern()
    blob += b"https://c2.example.invalid/checkin\n"
    blob += b"/tmp/suspicious_payload\n"
    blob += b"\x00" * (PAGE * 2)

    os.write(fd, bytes(blob[:PAGE * 2]))
    os.lseek(fd, 0, os.SEEK_SET)

    mapping = mmap.mmap(
        fd,
        PAGE * 2,
        prot=mmap.PROT_READ | mmap.PROT_EXEC,
        flags=mmap.MAP_PRIVATE,
    )

    return fd, mapping


def try_raw_socket():
    print("[test] attempting raw socket open")

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        print("[test] raw socket opened")
        return s
    except PermissionError:
        print("[test] raw socket denied; run with sudo if you want that heuristic")
        return None
    except OSError as exc:
        print(f"[test] raw socket unavailable: {exc}")
        return None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sleep", type=int, default=90, help="seconds to keep mappings alive")
    parser.add_argument("--raw-socket", action="store_true", help="try to open a raw socket")
    args = parser.parse_args()

    print(f"[test] pid={os.getpid()}")
    print(f"[test] arch={platform.machine()}")

    rwx = create_rwx_mapping()
    memfd = create_exec_memfd_mapping()
    raw_sock = try_raw_socket() if args.raw_socket else None

    print("[test] memory heuristic artifacts are live")
    print("[test] keep this process running while SignalHunter scans it")
    print(f"[test] sleeping {args.sleep}s")

    try:
        time.sleep(args.sleep)
    finally:
        if raw_sock is not None:
            raw_sock.close()

        if memfd is not None:
            fd, mapping = memfd
            mapping.close()
            os.close(fd)

        rwx.close()


if __name__ == "__main__":
    main()
