# Security & Safety Model (`linux-perf-doctor`)

## Core Security Guarantees
1. **Read-Only Default Execution**: All default diagnostic scripts read kernel virtual filesystems (`/proc`, `/sys/fs/cgroup`) and never modify sysctl parameters, kill processes, or alter scheduling priorities.
2. **Zero Automatic Privilege Escalation**: No script invokes `sudo`, `su`, or `pkexec`. When unprivileged execution encounters `PermissionError` (such as `/proc/<pid>/io` on processes owned by another UID), the collector records a non-fatal warning and continues.
3. **Explicit Consent for Active Profilers**: `scripts/profile_process.sh` refuses to run `strace` or `perf` unless `--enable-active-profiling` is explicitly passed, and enforces hard `timeout` bounds (max 30 seconds).
4. **No Secret Exposure**: Process environment variables (`/proc/<pid>/environ`) are never collected or printed by any script in this repository.
