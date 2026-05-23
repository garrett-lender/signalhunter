CC ?= cc
CLANG ?= clang

CFLAGS ?= -Wall -Wextra -O2 -std=c11
CPPFLAGS ?= -Iinclude/signalhunter -Iinclude

WITH_EBPF ?= 0

HOST_TRIPLE := $(shell gcc -dumpmachine)
BPF_ARCH ?= $(shell scripts/bpf_arch.sh)

ifeq ($(BPF_ARCH),arm64)
BPF_CROSS_TRIPLE ?= aarch64-linux-gnu
else ifeq ($(BPF_ARCH),arm)
BPF_CROSS_TRIPLE ?= arm-linux-gnueabihf
else ifeq ($(BPF_ARCH),mips)
BPF_CROSS_TRIPLE ?= mips-linux-gnu
else ifeq ($(BPF_ARCH),powerpc)
BPF_CROSS_TRIPLE ?= powerpc64le-linux-gnu
else ifeq ($(BPF_ARCH),riscv)
BPF_CROSS_TRIPLE ?= riscv64-linux-gnu
else ifeq ($(BPF_ARCH),s390)
BPF_CROSS_TRIPLE ?= s390x-linux-gnu
else
BPF_CROSS_TRIPLE ?= $(HOST_TRIPLE)
endif

BPF_NATIVE_INCLUDE := /usr/include/$(HOST_TRIPLE)
BPF_CROSS_INCLUDE := /usr/$(BPF_CROSS_TRIPLE)/include

ifndef BPF_INCLUDE
ifneq ($(wildcard $(BPF_CROSS_INCLUDE)/asm/types.h),)
BPF_INCLUDE := $(BPF_CROSS_INCLUDE)
else ifneq ($(wildcard /usr/include/$(BPF_CROSS_TRIPLE)/asm/types.h),)
BPF_INCLUDE := /usr/include/$(BPF_CROSS_TRIPLE)
else ifneq ($(wildcard $(BPF_NATIVE_INCLUDE)/asm/types.h),)
BPF_INCLUDE := $(BPF_NATIVE_INCLUDE)
else
BPF_INCLUDE := $(BPF_CROSS_INCLUDE)
endif
endif

BPF_BASE_CFLAGS := -O2 -g -target bpf
BPF_CFLAGS ?= $(BPF_BASE_CFLAGS) -D__TARGET_ARCH_$(BPF_ARCH)

SRCS = \
	src/app/main.c \
	src/core/score.c \
	src/core/lineage.c \
	src/core/module.c \
	src/core/event.c \
	src/core/util.c \
	src/case/case.c \
	src/case/inspect.c \
	src/detect/inject.c \
	src/detect/memscan.c \
	src/detect/shellcode.c \
	src/net/netmon.c \
	src/platform/ebpfmon.c \
	src/platform/fanmon.c \
	src/platform/proc_events.c \
	src/crypto/sha256.c

OBJS := $(SRCS:.c=.o)

LDLIBS =

ifeq ($(WITH_EBPF),1)
CPPFLAGS += -DRW_WITH_EBPF
LDLIBS += -lbpf -lelf -lz
endif

all: signalhunter

signalhunter: $(OBJS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $(OBJS) $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

check-bpf-include:
	@echo "BPF target arch: $(BPF_ARCH)"
	@echo "BPF cross triple: $(BPF_CROSS_TRIPLE)"
	@echo "BPF include path: $(BPF_INCLUDE)"
	@if [ ! -f "$(BPF_INCLUDE)/asm/types.h" ]; then \
		echo "error: $(BPF_INCLUDE)/asm/types.h not found"; \
		echo ""; \
		echo "Try one of:"; \
		echo "  sudo apt install linux-libc-dev"; \
		echo "  sudo apt install libc6-dev-arm64-cross"; \
		echo "  make ebpf BPF_ARCH=arm64 BPF_INCLUDE=/usr/aarch64-linux-gnu/include"; \
		echo ""; \
		echo "Available asm/types.h candidates:"; \
		find /usr/include /usr -path '*/asm/types.h' 2>/dev/null | head -20; \
		exit 1; \
	fi

signalhunter_ebpf.bpf.o: src/ebpf/signalhunter_ebpf.bpf.c | check-bpf-include
	$(CLANG) $(BPF_CFLAGS) -I$(BPF_INCLUDE) -I/usr/include \
		-c $< -o $@

ebpf:
	$(MAKE) WITH_EBPF=1
	$(MAKE) signalhunter_ebpf.bpf.o \
		WITH_EBPF=1 \
		BPF_ARCH="$(BPF_ARCH)" \
		BPF_INCLUDE="$(BPF_INCLUDE)" \
		BPF_CFLAGS='$(BPF_CFLAGS)'

clean:
	rm -f signalhunter signalhunter_ebpf.bpf.o
	find src -name '*.o' -delete
	rm -rf logs/

.PHONY: all clean ebpf check-bpf-include
