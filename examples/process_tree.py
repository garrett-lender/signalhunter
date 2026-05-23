#!/usr/bin/env python3
"""
SignalHunter process lineage / process tree trigger.

Creates:

parent
 └── child
      └── grandchild

The grandchild creates:
  - RWX anonymous mapping
  - executable memfd mapping
  - suspicious strings
  - architecture-specific NOP patterns
"""

import mmap
import os
import platform
import time

PAGE = 4096


def arch_nops() -> bytes:
    machine = platform.machine().lower()

    if machine in ("x86_64", "amd64", "i386", "i686"):
        return b"\x90" * 512

    if machine in ("aarch64", "arm64"):
        return b"\x1f\x20\x03\xd5" * 128

    if machine.startswith("arm"):
        return b"\x00\x00\xa0\xe1" * 128

    if "mips" in machine:
        return b"\x00\x00\x00\x00" * 128

    return b"\x90" * 512


def suspicious_memory():
    print(f"[grandchild] pid={os.getpid()} creating RWX mapping")

    m = mmap.mmap(
        -1,
        PAGE * 4,
        prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC,
    )

    blob = bytearray()

    blob += b"SIGNALHUNTER_TREE_TEST\n"
    blob += arch_nops()
    blob += b"\x7fELF"
    blob += b"\x00" * 128
    blob += b"http://tree-test.invalid/beacon\n"
    blob += b"/tmp/tree_payload\n"
    blob += b"LD_PRELOAD=/tmp/fake.so\n"

    m.write(bytes(blob[:PAGE * 4]))

    fd = None
    memfd_map = None

    if hasattr(os, "memfd_create"):
        fd = os.memfd_create("signalhunter_tree_test", flags=0)
        os.ftruncate(fd, PAGE * 2)

        os.write(fd, bytes(blob[:PAGE * 2]))
        os.lseek(fd, 0, os.SEEK_SET)

        memfd_map = mmap.mmap(
            fd,
            PAGE * 2,
            prot=mmap.PROT_READ | mmap.PROT_EXEC,
            flags=mmap.MAP_PRIVATE,
        )

        print("[grandchild] executable memfd mapping created")

    print("[grandchild] sleeping for scanner visibility")
    time.sleep(90)

    if memfd_map is not None:
        memfd_map.close()

    if fd is not None:
        os.close(fd)

    m.close()


def grandchild():
    print(f"[grandchild] pid={os.getpid()} ppid={os.getppid()}")
    suspicious_memory()


def child():
    print(f"[child] pid={os.getpid()} ppid={os.getppid()}")

    pid = os.fork()

    if pid == 0:
        grandchild()
        os._exit(0)

    os.waitpid(pid, 0)


def parent():
    print(f"[parent] pid={os.getpid()}")

    pid = os.fork()

    if pid == 0:
        child()
        os._exit(0)

    os.waitpid(pid, 0)


if __name__ == "__main__":
    parent()
