#!/usr/bin/env python3
"""
SignalHunter process lineage / process tree trigger.

Creates:

python parent
 └── python child
      ├── python grandchild
      │    ├── RWX anonymous mmap
      │    └── executable memfd mmap
      └── /bin/sh child-exec target
           └── /usr/bin/sleep

This helps test:
  - parent -> child -> grandchild lineage
  - child spawning a different executable
  - exec path changes in process_tree.txt / lineage.tsv
  - suspicious memory heuristics
  - case generation
"""

import mmap
import os
import platform
import subprocess
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


def suspicious_memory() -> None:
    print(f"[grandchild] pid={os.getpid()} creating RWX mapping", flush=True)

    rwx = mmap.mmap(
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

    blob = bytes(blob[: PAGE * 4])
    rwx.write(blob)

    fd = None
    memfd_map = None

    if hasattr(os, "memfd_create"):
        print("[grandchild] creating executable memfd mapping", flush=True)

        fd = os.memfd_create("signalhunter_tree_test", flags=0)
        os.ftruncate(fd, PAGE * 2)
        os.write(fd, blob[: PAGE * 2])
        os.lseek(fd, 0, os.SEEK_SET)

        memfd_map = mmap.mmap(
            fd,
            PAGE * 2,
            prot=mmap.PROT_READ | mmap.PROT_EXEC,
            flags=mmap.MAP_PRIVATE,
        )

        print("[grandchild] executable memfd mapping created", flush=True)

    print("[grandchild] sleeping for scanner visibility", flush=True)
    time.sleep(90)

    if memfd_map is not None:
        memfd_map.close()

    if fd is not None:
        os.close(fd)

    rwx.close()


def spawn_different_exe_child() -> subprocess.Popen:
    """
    Spawn a process with a different executable than Python.

    /bin/sh is the direct child, then it execs/runs /usr/bin/sleep.
    This should show a different exe path in lineage/case artifacts.
    """
    print(f"[child] spawning different exe: /bin/sh -c 'sleep 90'", flush=True)

    return subprocess.Popen(
        ["/bin/sh", "-c", "echo '[sh-child] pid=$$ ppid=$PPID'; exec sleep 90"],
        stdout=None,
        stderr=None,
    )


def grandchild() -> None:
    print(f"[grandchild] pid={os.getpid()} ppid={os.getppid()}", flush=True)
    suspicious_memory()


def child() -> None:
    print(f"[child] pid={os.getpid()} ppid={os.getppid()}", flush=True)

    sh_proc = spawn_different_exe_child()

    pid = os.fork()

    if pid == 0:
        grandchild()
        os._exit(0)

    try:
        os.waitpid(pid, 0)
    finally:
        try:
            sh_proc.terminate()
            sh_proc.wait(timeout=5)
        except Exception:
            try:
                sh_proc.kill()
            except Exception:
                pass


def parent() -> None:
    print(f"[parent] pid={os.getpid()}", flush=True)

    pid = os.fork()

    if pid == 0:
        child()
        os._exit(0)

    os.waitpid(pid, 0)


if __name__ == "__main__":
    parent()
