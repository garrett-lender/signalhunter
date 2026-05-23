# SignalHunter

SignalHunter is a Linux process, network, memory, and behavioral monitoring tool written in C.

It is organized as a small daemon with capability-focused libraries. The goal is to keep the core loop simple while making each detector easier to maintain, replace, or eventually load dynamically.

## What SignalHunter Does

SignalHunter monitors Linux systems for suspicious process behavior using:

- `/proc` process and network inspection
- process lineage tracking
- global per-process scoring
- forensic case creation
- memory-map injection detection
- bounded `/proc/<pid>/mem` inspection
- architecture-aware shellcode/NOP heuristics
- fanotify filesystem monitoring
- optional eBPF syscall/network telemetry
- local SHA-256 hashing with no OpenSSL dependency

SignalHunter is alert-first. It does not kill or stop processes by default.

## Code Layout

```text
signalhunter/
├── include/
│   └── signalhunter/
│       ├── signalhunter.h      # shared public project declarations
│       ├── score.h             # global per-process score model
│       ├── memscan.h           # bounded memory scanner API
│       ├── shellcode.h         # shellcode/NOP heuristic API
│       └── sha256.h            # local SHA-256 API
├── src/
│   ├── app/
│   │   └── main.c              # daemon startup, CLI args, main loop
│   ├── core/
│   │   ├── score.c             # cumulative process scoring and thresholds
│   │   └── util.c              # logging, files, common helpers
│   ├── case/
│   │   ├── case.c              # forensic case creation and artifacts
│   │   └── inspect.c           # process snapshot helpers
│   ├── detect/
│   │   ├── inject.c            # maps-based injection heuristics
│   │   ├── memscan.c           # /proc/<pid>/mem scanner
│   │   └── shellcode.c         # architecture-aware shellcode heuristics
│   ├── net/
│   │   └── netmon.c            # TCP/socket monitoring and beacon scoring
│   ├── platform/
│   │   ├── ebpfmon.c           # userspace eBPF loader/event handler
│   │   ├── fanmon.c            # fanotify filesystem monitor
│   │   └── proc_events.c       # process lifecycle backend
│   ├── crypto/
│   │   └── sha256.c            # endian-safe SHA-256 implementation
│   └── ebpf/
│       └── signalhunter_ebpf.bpf.c
├── examples/
│   └── *.py                    # benign trigger examples
├── scripts/
│   └── bpf_arch.sh             # BPF target arch helper
└── Makefile
```

## Capability Libraries

### app

Owns CLI parsing and the daemon loop.

### core

Owns shared utilities and the global score engine. Detectors should report behavior through the score engine instead of directly opening cases.

### case

Owns forensic case directories and process snapshots. Case artifacts include process metadata, maps, file descriptors, score timelines, and memory findings when available.

### detect

Owns behavioral and memory detections, including injection checks, memory scanning, and shellcode/NOP heuristics.

### net

Owns network visibility and beacon/scan-style behavior detection.

### platform

Owns OS-specific event backends such as fanotify, proc connector, and eBPF loader code.

### crypto

Owns the local SHA-256 implementation. SignalHunter no longer depends on OpenSSL for hashing.

### ebpf

Contains the kernel-side eBPF C source.

## Build

### Standard build

```bash
make
```

### eBPF build

```bash
make ebpf
```

For ARM64 cross-builds:

```bash
make clean
make ebpf \
  CC=aarch64-linux-gnu-gcc \
  BPF_ARCH=arm64 \
  BPF_INCLUDE=/usr/aarch64-linux-gnu/include
```

The userspace binary and eBPF object are separate outputs:

```text
signalhunter              # userspace daemon
signalhunter_ebpf.bpf.o   # eBPF bytecode object
```

## Run

```bash
sudo ./signalhunter
```

Verbose mode:

```bash
sudo ./signalhunter --verbose
```

Case threshold example:

```bash
sudo ./signalhunter --case-threshold 85 --injection-scan-seconds 2
```

## Logs and Cases

Runtime logs are written under:

```text
logs/
```

Case directories are written under:

```text
logs/cases/
```

Each case is intended to preserve triage data for one suspicious process, including score history and available process artifacts.

## Examples

Benign trigger examples are under:

```text
examples/
```

Useful examples include:

- heartbeat/reconnect beaconing
- RWX mmap
- executable memfd mapping
- raw socket opening
- localhost scan-like connects
- execution from `/tmp`

## Design Direction

The current structure is ready for a plugin-style architecture. The next step is to define a common module interface, for example:

```c
typedef struct sh_module {
    const char *name;
    int (*init)(void);
    int (*poll)(void);
    void (*shutdown)(void);
} sh_module_t;
```

Static modules can use that interface first. Dynamic loading via `dlopen()` can be added later without changing detector internals.


## Useful Testing Option

For memory/injection heuristic testing, shorten the full injection scan interval:

```bash
sudo ./signalhunter --case-threshold 85 --injection-scan-seconds 2 --verbose
```

This makes RWX/memfd mapping test scripts score quickly enough to create cases.


## Module Architecture

SignalHunter uses a static module interface for event backends. The interface is defined in:

```text
include/signalhunter/module.h
src/core/module.c
```

A module is represented as:

```c
typedef struct rw_module {
    const char *name;
    int initialized;
    int fd;
    void *state;

    int (*enabled)(const rw_config_t *cfg);
    int (*init)(struct rw_module *module, const rw_config_t *cfg);
    void (*poll)(struct rw_module *module, const rw_config_t *cfg);
    void (*shutdown)(struct rw_module *module);
} rw_module_t;
```

Current static modules:

- `proc_connector`
- `fanotify`
- `ebpf`

The daemon initializes enabled modules at startup and polls them through the module manager. This keeps detector internals separated from the app loop and prepares the project for future dynamic loading via `dlopen()`/`dlsym()`.

## Event Timeline and Tree Manifest

SignalHunter keeps a bounded in-memory event timeline. Scoring, process lifecycle events, and other detector activity are recorded through the central event API. When a case is opened or updated, SignalHunter exports related events and lineage artifacts into the case directory.

Case lineage/timeline artifacts include:

```text
timeline.txt
tree_manifest.tsv
lineage.tsv
process_tree.txt
```

`timeline.txt` contains timestamped related events for the suspicious process family. `tree_manifest.tsv` contains the observed process family with PID, PPID, command name, executable path, command line, timestamps, and exit state.
