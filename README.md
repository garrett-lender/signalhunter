# SignalHunter

SignalHunter is a modular Linux behavioral monitoring and telemetry platform written in C.

It combines process monitoring, process lineage, eBPF syscall telemetry, network monitoring, injection detection, bounded memory inspection, shellcode heuristics, filesystem monitoring, global risk scoring, and forensic case generation.

SignalHunter is intended as a defensive Linux telemetry and EDR-style research platform.

---

## Major capabilities

### Process monitoring

SignalHunter tracks visible Linux processes and collects:

- PID and PPID
- executable path
- command line
- cwd/root
- environment
- memory maps
- open file descriptors
- process lifecycle events
- exec transitions

### Process lineage

SignalHunter maintains parent/child process relationships and exports process trees in cases.

Case artifacts include:

```text
process_tree.txt
lineage.tsv
tree_manifest.tsv
timeline.txt
```

### Network monitoring

SignalHunter monitors TCP/socket behavior and scores:

- beacon-like reconnect timing
- heartbeat intervals
- rapid connection bursts
- SYN-scan-like behavior
- raw sockets
- packet sockets
- unusual socket usage

### Injection detection

SignalHunter scans `/proc/<pid>/maps` for:

- RWX mappings
- anonymous executable mappings
- executable memfd mappings
- deleted executable mappings
- executable mappings from suspicious paths
- ptrace indicators

### Memory inspection

SignalHunter performs bounded `/proc/<pid>/mem` inspection on suspicious mappings only.

Memory case artifacts may include:

```text
memory_findings.txt
memory_strings.txt
mem_region_000.bin
```

### Shellcode heuristics

SignalHunter includes architecture-aware shellcode/NOP heuristics for:

- x86
- x86_64
- ARM
- ARM64
- MIPS big-endian and little-endian patterns

Heuristics include:

- NOP sled detection
- syscall stub detection
- ELF headers in suspicious memory
- PE headers in suspicious memory
- suspicious executable memory patterns

### Optional eBPF telemetry

When built with `make ebpf`, SignalHunter can monitor low-level syscall/socket behavior including:

- `ptrace`
- executable `mmap` / `mprotect`
- `memfd_create`
- raw socket creation
- connect activity
- `process_vm_readv` / `process_vm_writev`
- exec activity

### Filesystem monitoring

fanotify support detects suspicious filesystem activity, including:

- executable access
- execution from temporary paths
- chmod/executable permission changes
- temporary executable creation

---

## Risk scoring v2

SignalHunter now uses an explainable risk model instead of simple flat additive scoring.

Detectors still call:

```c
rw_score_add(...)
```

Internally, scoring now uses:

- typed findings
- category buckets
- risk floors for critical signals
- score decay
- correlation bonuses
- explainable case summaries

Risk categories:

```text
memory
network
process
filesystem
lineage
```

Examples of correlations:

```text
executable memfd + NOP/shellcode pattern
executable memory anomaly + beacon/connect behavior
RWX memory + raw/packet socket
temporary-path execution + beacon/connect behavior
raw/packet socket + scan-like behavior
ptrace + process_vm activity
PE/ELF header in suspicious RWX memory
```

Cases include:

```text
risk_summary.txt
score_timeline.log
```

`risk_summary.txt` explains:

- current risk
- peak risk
- category scores
- correlation bonus
- risk floor
- top recent scoring events

---

## Forensic cases

When a process crosses the case threshold, SignalHunter creates:

```text
logs/cases/pid_<pid>_<timestamp>/
```

Possible artifacts:

```text
case.log
actions.log
risk_summary.txt
score_timeline.log
timeline.txt

cmdline.bin
status.txt
maps.txt
fds.txt
environ.bin

process_tree.txt
lineage.tsv
tree_manifest.tsv

memory_findings.txt
memory_strings.txt
mem_region_000.bin

exe.dump
exe.sha256
```

SignalHunter attempts to write placeholder/error files when a process exits before evidence can be collected.

---

## Modular architecture

Source layout:

```text
include/signalhunter/

src/
├── app/
├── case/
├── core/
├── crypto/
├── detect/
├── ebpf/
├── net/
└── platform/
```

Runtime modules are initialized/polled through the module manager.

Current module-oriented components include:

- proc connector
- fanotify
- eBPF
- network monitor
- injection monitor
- lineage refresh
- score maintenance
- case maintenance

The static module interface is intended to support future `dlopen()`-based dynamic modules.

---

## Build

Standard build:

```bash
make
```

Clean:

```bash
make clean
```

### eBPF build

Install dependencies:

```bash
sudo apt install \
  clang \
  llvm \
  libbpf-dev \
  libelf-dev \
  zlib1g-dev \
  linux-libc-dev \
  linux-headers-$(uname -r)
```

Build:

```bash
make ebpf
```

### ARM64 cross-build

Install cross compiler:

```bash
sudo apt install gcc-aarch64-linux-gnu g++-aarch64-linux-gnu libc6-dev-arm64-cross
```

Build:

```bash
make clean
make ebpf \
  CC=aarch64-linux-gnu-gcc \
  BPF_ARCH=arm64 \
  BPF_INCLUDE=/usr/aarch64-linux-gnu/include
```

SignalHunter uses a local SHA-256 implementation, so OpenSSL development headers are not required.

---

## Run

Run with root privileges for best visibility:

```bash
sudo ./signalhunter --verbose
```

Use a custom case threshold:

```bash
sudo ./signalhunter --case-threshold 85 --verbose
```

Aggressive injection scan interval for testing:

```bash
sudo ./signalhunter --case-threshold 85 --injection-scan-seconds 1 --verbose
```

---

## Logs

Logs are written under:

```text
logs/
```

Common files:

```text
alerts.log
scores.log
network.log
injection.log
events.log
cases/
```

SignalHunter supports log rotation, archive retention, duplicate suppression, score logging, and case timelines.

---

## Example triggers

Examples live under:

```text
examples/
```

Useful tests:

```bash
python3 examples/test_mem_heuristics.py --sleep 90
python3 examples/test_process_tree_exec.py
python3 examples/heartbeat_reconnect.py
sudo python3 examples/raw_socket_open.py
```

For memory/shellcode testing, run SignalHunter with:

```bash
sudo ./signalhunter --case-threshold 85 --injection-scan-seconds 1 --verbose
```

Then run:

```bash
python3 examples/test_mem_heuristics.py --sleep 90
```

Expected case artifacts include:

```text
risk_summary.txt
memory_findings.txt
score_timeline.log
timeline.txt
tree_manifest.tsv
process_tree.txt
```

---

## Notes

SignalHunter is an evolving research platform, not a production security product. It is designed for defensive monitoring, Linux telemetry research, detection engineering, and EDR prototyping.
