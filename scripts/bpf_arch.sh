#!/bin/sh
set -eu
arch="$(uname -m)"
case "$arch" in
    x86_64|amd64|i386|i686)
        echo x86
        ;;
    aarch64|arm64)
        echo arm64
        ;;
    arm*)
        echo arm
        ;;
    mips*|mips64*)
        echo mips
        ;;
    ppc64*|powerpc64*)
        echo powerpc
        ;;
    riscv64)
        echo riscv
        ;;
    s390x)
        echo s390
        ;;
    *)
        echo x86
        ;;
esac
