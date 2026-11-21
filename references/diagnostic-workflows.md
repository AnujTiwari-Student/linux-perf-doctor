# Diagnostic Workflows (`linux-perf-doctor`)

## Workflow 1: High Tail Latency with Low Host CPU
1. Run `python3 scripts/inspect_cgroups.py --pretty`.
2. Check `metrics.cpu.throttle_pct` and `metrics.cpu.nr_throttled`.
3. If `throttle_pct > 5%`, compare `metrics.cpu.effective_cpus` against the process thread count (`metrics.threads` from `scripts/collect_process_metrics.py`).
4. Remediation: Set runtime thread pools (`GOMAXPROCS`, `OMP_NUM_THREADS`) to match `ceil(effective_cpus)` or raise container CPU limits.

## Workflow 2: Memory Growth vs Kernel OOM Investigation
1. Run `python3 scripts/collect_system_metrics.py --pretty` and `python3 scripts/inspect_cgroups.py --pretty`.
2. Inspect `vmstat.oom_kill` and `cgroup.memory.events.oom_kill`.
3. Identify top RSS processes via `python3 scripts/collect_process_metrics.py --top 10 --pretty`.
4. Sample the target PID over 3 intervals to verify whether `VmRSS` grows monotonically.

## Workflow 3: High System CPU (`sy`) and Context Switch Storm
1. Confirm `system_pct > 25%` and `ctxt_per_sec` spike via `scripts/collect_system_metrics.py`.
2. Check `voluntary_ctxt_switches` vs `nonvoluntary_ctxt_switches` on the target PID.
3. With explicit user authorization, run `bash scripts/profile_process.sh --pid <PID> --mode strace-summary --duration 3 --enable-active-profiling` to pinpoint dominant syscalls (`futex`, `read`, `write`, `epoll_wait`).
