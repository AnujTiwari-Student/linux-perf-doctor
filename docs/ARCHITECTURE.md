# Architecture: `linux-perf-doctor`

## Overview
`linux-perf-doctor` follows a strictly layered, read-only-first diagnostic pipeline:

1. **Capability Probe Layer (`scripts/check_perf_capabilities.sh`)**: Inspects installed binaries, kernel sysctl security guards (`perf_event_paranoid`, `ptrace_scope`, `kptr_restrict`), and mounted filesystems (`/proc`, `/sys/fs/cgroup`, `/proc/pressure`).
2. **Subsystem Collector Layer**:
   - `scripts/collect_system_metrics.py`: Computes CPU tick deltas, run-queue depth, memory utilization, `/proc/vmstat` OOM/fault counters, and PSI stall ratios.
   - `scripts/collect_process_metrics.py`: Parses `/proc/<pid>/stat`, `status`, `io`, and `fd` descriptors.
   - `scripts/inspect_cgroups.py`: Evaluates both cgroup v2 (`cpu.max`, `cpu.stat`, `memory.current`, `memory.events`) and cgroup v1 (`cpu.cfs_quota_us`, `memory.usage_in_bytes`).
   - `scripts/inspect_io.sh` & `scripts/inspect_network.py`: Parses `/proc/diskstats`, `/proc/net/tcp`, `/proc/net/tcp6`, and `/proc/net/dev`.
3. **Opt-In Active Profiler (`scripts/profile_process.sh`)**: Gated behind `--enable-active-profiling` to prevent unintended process pauses.
4. **Correlation & Reporting Engine (`scripts/generate_report.py`)**: Combines all subsystem outputs, distinguishes `"measured"` findings from `"hypothesis"` correlations, and emits JSON or Markdown.
