# Technical Reference: Linux Telemetry & Kernel Counters

## 1. `/proc/stat` and CPU Accounting
- **`user` / `nice`**: Ticks spent executing user-space code. High values indicate CPU-bound loops, serialization, compression, or cryptographic routines.
- **`system` / `irq` / `softirq`**: Ticks spent inside kernel space. Values above 25% of total non-idle CPU indicate excessive system calls, mutex contention (`futex`), VFS path walks, or network packet processing.
- **`iowait`**: Ticks during which the CPU was idle while at least one outstanding disk I/O operation was requested on that core.
- **`steal`**: Ticks where a hypervisor scheduled another guest VM while the virtual CPU was runnable.

## 2. Pressure Stall Information (`/proc/pressure/{cpu,memory,io}`)
- **`some`**: Percentage of wall-clock time in which at least one runnable task was delayed due to resource contention.
- **`full`**: Percentage of wall-clock time in which *all* non-idle tasks were simultaneously stalled waiting for the resource (e.g., direct memory reclaim or storage flush).

## 3. Cgroup v2 (`cpu.max`, `cpu.stat`, `memory.current`, `memory.events`)
- **`cpu.max`**: Format `<quota_us> <period_us>`. A value of `50000 100000` allocates 50ms per 100ms window (0.5 effective cores). Multi-threaded apps with 8 worker threads can exhaust a 50ms quota in 6.25ms of wall-clock time and sit throttled for the remaining 93.75ms.
- **`memory.events`**:
  - `high`: Count of times the cgroup exceeded the soft throttle threshold (`memory.high`), forcing processes into direct reclaim.
  - `max`: Count of times the cgroup hit `memory.max` and attempted emergency memory reclaim.
  - `oom_kill`: Count of processes terminated inside the cgroup by the kernel OOM killer.
