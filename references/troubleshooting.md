# Troubleshooting & Environment Limitations

## 1. `perf_event_paranoid` Permission Denials
- **Symptom**: `perf stat` exits with permission denied for unprivileged users.
- **Cause**: `/proc/sys/kernel/perf_event_paranoid` is set to `2`, `3`, or `4` (common on Ubuntu/Debian and hardened kernels).
- **Resolution**: `linux-perf-doctor` automatically falls back to `/proc/<pid>/stat` software tick accounting and `/proc/pressure` PSI metrics without failing the diagnostic pipeline.

## 2. `ptrace_scope` Restrictions in Containers
- **Symptom**: `strace -p <PID>` fails with `Operation not permitted`.
- **Cause**: Yama `ptrace_scope=1` or Docker default seccomp profile blocking `ptrace` without `CAP_SYS_PTRACE`.
- **Resolution**: Use passive `/proc/<pid>/status` context-switch metrics and `/proc/<pid>/wchan`.

## 3. Container Missing `/proc/diskstats`
- **Symptom**: `scripts/inspect_io.sh` emits a warning that `/proc/diskstats` is absent.
- **Cause**: Restricted container `/proc` mount.
- **Resolution**: Inspect per-process `/proc/<pid>/io` and `/proc/pressure/io` instead.
