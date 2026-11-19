# Linux Performance Diagnostic Report (`linux-perf-doctor`)

- **Overall Health Status**: `CRITICAL`
- **Timestamp (UTC)**: `2026-11-17T16:16:25.157691+00:00`
- **Kernel / Arch**: `6.12.105+` (`x86_64`)

## 1. Detected Bottlenecks & Hypotheses

### [HIGH] SYS-CPU-001: High CPU utilization detected (96.86% busy)
- **Classification**: `measured` (Confidence: `high`)
- **Evidence**: `{"busy_pct": 96.86, "user_pct": 56.85, "system_pct": 22.3, "procs_running": 12, "cpu_count": 2, "semantics": "cumulative_since_boot"}`
- **Likely Causes**: Compute-bound worker loops or serialization overhead
- **Recommended Action**: Inspect top CPU-consuming PIDs with scripts/collect_process_metrics.py and check cgroup throttling.

### [MEDIUM] SYS-IO-001: Elevated I/O wait (17.59%) or blocked tasks (4)
- **Classification**: `measured` (Confidence: `high`)
- **Evidence**: `{"iowait_pct": 17.59, "procs_blocked": 4, "psi_io": {"some": {"avg10": 55.0, "avg60": 40.0, "avg300": 25.0, "total": 12500000.0}, "full": {"avg10": 38.2, "avg60": 29.0, "avg300": 15.0, "total": 8400000.0}}}`
- **Likely Causes**: Synchronous disk writes (fsync/fdatasync) saturating backing storage; Memory pressure causing major page faults and swap I/O
- **Recommended Action**: Run scripts/inspect_io.sh to inspect per-device await/utilization and identify uninterruptible sleep (D-state) processes.

### [HIGH] SYS-MEM-001: High system memory utilization (95.0% used)
- **Classification**: `measured` (Confidence: `high`)
- **Evidence**: `{"mem_total_bytes": 16777216000, "mem_available_bytes": 838860800, "mem_used_pct": 95.0, "swap_used_pct": 75.0}`
- **Likely Causes**: Unbounded application heap or cache growth; Insufficient container or VM memory allocation relative to worker concurrency
- **Recommended Action**: Check process RSS growth using scripts/collect_process_metrics.py and verify cgroup memory.max limits.

### [HIGH] SYS-MEM-002: Kernel OOM killer invocations recorded (oom_kill=3)
- **Classification**: `measured` (Confidence: `high`)
- **Evidence**: `{"vmstat_oom_kill": 3, "pgmajfault": 18450}`
- **Likely Causes**: Host or cgroup memory exhaustion triggering Linux OOM killer
- **Recommended Action**: Inspect cgroup memory.events for oom_kill counters and set bounded heap limits on worker processes.

### [HIGH] CGRP-CPU-001: Container CFS CPU throttling detected (35.0% of periods throttled)
- **Classification**: `measured` (Confidence: `high`)
- **Evidence**: `{"cpu_max_raw": "50000 100000", "quota_us": 50000, "period_us": 100000, "effective_cpus": 0.5, "nr_periods": 12000, "nr_throttled": 4200, "throttled_usec": 540000000, "throttle_pct": 35.0}`
- **Likely Causes**: Multi-threaded application bursting above container CPU quota within 100ms period; Restrictive Kubernetes/Docker CPU limit relative to worker thread count
- **Recommended Action**: Increase container CPU limit or tune runtime worker threads (e.g., GOMAXPROCS, UV_THREADPOOL_SIZE) to match effective CPU quota.

### [CRITICAL] CGRP-MEM-001: Cgroup OOM events recorded (oom_kill=2, oom=4)
- **Classification**: `measured` (Confidence: `high`)
- **Evidence**: `{"current_bytes": 966367641, "max_bytes": 1073741824, "utilization_pct": 90.0, "events": {"low": 0, "high": 450, "max": 82, "oom": 4, "oom_kill": 2}}`
- **Likely Causes**: Container memory working set exceeded cgroup memory limit
- **Recommended Action**: Increase container memory limit or configure runtime heap bounds (e.g., NODE_OPTIONS=--max-old-space-size, GOMEMLIMIT) below cgroup memory ceiling.

### [HIGH] CGRP-PSI-001: Elevated per-cgroup Pressure Stall Information (memory full avg10=11.8%, io full avg10=31.4%)
- **Classification**: `measured` (Confidence: `high`)
- **Evidence**: `{"cpu": {"some": {"avg10": 38.5, "avg60": 29.1, "avg300": 18.0, "total": 7400000.0}, "full": {"avg10": 21.2, "avg60": 15.4, "avg300": 9.1, "total": 3900000.0}}, "memory": {"some": {"avg10": 24.0, "avg60": 18.2, "avg300": 9.5, "total": 3100000.0}, "full": {"avg10": 11.8, "avg60": 7.4, "avg300": 3.2, "total": 1450000.0}}, "io": {"some": {"avg10": 49.0, "avg60": 35.0, "avg300": 22.0, "total": 9200000.0}, "full": {"avg10": 31.4, "avg60": 24.1, "avg300": 14.0, "total": 6100000.0}}}`
- **Likely Causes**: Cgroup tasks stalled on direct memory reclaim or cgroup I/O throttling
- **Recommended Action**: Inspect cgroup memory.high/memory.max and io.max limits.

### [MEDIUM] NET-TCP-001: High CLOSE_WAIT socket accumulation (65 sockets)
- **Classification**: `measured` (Confidence: `high`)
- **Evidence**: `{"close_wait_count": 65, "state_counts": {"ESTABLISHED": 0, "SYN_SENT": 0, "SYN_RECV": 0, "FIN_WAIT1": 0, "FIN_WAIT2": 0, "TIME_WAIT": 0, "CLOSE": 0, "CLOSE_WAIT": 65, "LAST_ACK": 0, "LISTEN": 0, "CLOSING": 0}}`
- **Likely Causes**: Application failing to call close() on sockets after remote peer FIN disconnect; Worker thread starvation preventing socket cleanup
- **Recommended Action**: Audit application connection pool lifecycle and ensure HTTP/DB client connections are closed in finally/defer blocks.

### [MEDIUM] NET-SNMP-RETRANS: Elevated TCP segment retransmission rate (2.3%: 18400/800000 segments)
- **Classification**: `measured` (Confidence: `high`)
- **Evidence**: `{"out_segs_cumulative": 800000, "retrans_segs_cumulative": 18400, "retrans_pct": 2.3, "estab_resets": 185}`
- **Likely Causes**: Network congestion, NIC ring buffer drops, or cloud virtual switch bandwidth policing
- **Recommended Action**: Check interface tx_drop/rx_drop counters and TCP congestion control settings.

### [MEDIUM] NET-SNMP-UDPBUF: UDP socket receive buffer drops recorded (RcvbufErrors=24)
- **Classification**: `measured` (Confidence: `high`)
- **Evidence**: `{"udp_mib": {"InDatagrams": 120000, "NoPorts": 45, "InErrors": 28, "OutDatagrams": 118000, "RcvbufErrors": 24, "SndbufErrors": 0, "InCsumErrors": 0, "IgnoredMulti": 0, "MemErrors": 0}}`
- **Likely Causes**: net.core.rmem_max too small for burst UDP traffic (e.g., DNS/QUIC/StatsD)
- **Recommended Action**: Increase net.core.rmem_max or scale UDP reader threads.

### [HIGH] NET-NETSTAT-LISTEN: TCP listen queue overflows detected (ListenOverflows=340, ListenDrops=340)
- **Classification**: `measured` (Confidence: `high`)
- **Evidence**: `{"ListenOverflows": 340, "ListenDrops": 340, "TCPSynRetrans": 290, "TCPTimeouts": 190}`
- **Likely Causes**: Application accept() loop is stalled or net.core.somaxconn / net.ipv4.tcp_max_syn_backlog is undersized
- **Recommended Action**: Raise net.core.somaxconn and application listen() backlog parameter, and check worker CPU throttling.

### [MEDIUM] NET-QUEUE-001: Detected 65 sockets with elevated Recv-Q or Send-Q buffers
- **Classification**: `measured` (Confidence: `high`)
- **Evidence**: `{"queued_sockets": [{"table": "tcp", "local_address": "0100007F:1F90", "state": "CLOSE_WAIT", "tx_queue": 0, "rx_queue": 8192}, {"table": "tcp", "local_address": "0100007F:1F90", "state": "CLOSE_WAIT", "tx_queue": 0, "rx_queue": 8192}, {"table": "tcp", "local_address": "0100007F:1F90", "state": "CLOSE_WAIT", "tx_queue": 0, "rx_queue": 8192}, {"table": "tcp", "local_address": "0100007F:1F90", "state": "CLOSE_WAIT", "tx_queue": 0, "rx_queue": 8192}, {"table": "tcp", "local_address": "0100007F:1F90", "state": "CLOSE_WAIT", "tx_queue": 0, "rx_queue": 8192}, {"table": "tcp", "local_address": "0100007F:1F90", "state": "CLOSE_WAIT", "tx_queue": 0, "rx_queue": 8192}, {"table": "tcp", "local_address": "0100007F:1F90", "state": "CLOSE_WAIT", "tx_queue": 0, "rx_queue": 8192}, {"table": "tcp", "local_address": "0100007F:1F90", "state": "CLOSE_WAIT", "tx_queue": 0, "rx_queue": 8192}, {"table": "tcp", "local_address": "0100007F:1F90", "state": "CLOSE_WAIT", "tx_queue": 0, "rx_queue": 8192}, {"table": "tcp", "local_address": "0100007F:1F90", "state": "CLOSE_WAIT", "tx_queue": 0, "rx_queue": 8192}]}`
- **Likely Causes**: Slow application reader (high Recv-Q) or congested downstream receiver (high Send-Q)
- **Recommended Action**: Inspect stalled reader/writer processes holding queued sockets.

### [MEDIUM] NET-IFACE-001: Network interface packet drops or errors detected (total=547)
- **Classification**: `measured` (Confidence: `medium`)
- **Evidence**: `{"interfaces": {"eth0": {"rx_bytes": 99400000, "rx_packets": 85000, "rx_errs": 12, "rx_drop": 450, "tx_bytes": 88200000, "tx_packets": 79000, "tx_errs": 0, "tx_drop": 85}}}`
- **Likely Causes**: Ring buffer exhaustion, NIC IRQ saturation, or virtual bridge policing
- **Recommended Action**: Inspect per-interface rx_drop/tx_drop counts and verify ring buffer sizing.

### [HIGH] PROC-STATE-001: Process 4242 (order-worker) is in uninterruptible sleep (D state)
- **Classification**: `measured` (Confidence: `high`)
- **Evidence**: `{"pid": 4242, "comm": "order-worker", "state": "D", "iowait_sum_ms": 42300.75}`
- **Likely Causes**: Blocked on synchronous disk I/O, NFS mount stall, or kernel mutex contention
- **Recommended Action**: Inspect block device latency with scripts/inspect_io.sh and check /proc/<pid>/sched iowait_sum.

### [MEDIUM] PROC-SCHED-001: Process 4242 (order-worker) exhibits CPU run-queue contention or involuntary preemption
- **Classification**: `measured` (Confidence: `high`)
- **Evidence**: `{"runqueue_wait_sum_ms": 18450.25, "nr_migrations": 1840, "voluntary_ctxt_switches": 142000, "nonvoluntary_ctxt_switches": 89000}`
- **Likely Causes**: Thread count exceeds available CPU cores or cgroup CFS quota is throttling runnable threads
- **Recommended Action**: Compare process thread count against cgroup CPU quota using scripts/inspect_cgroups.py.

### [MEDIUM] PROC-MEM-001: Process 4242 experiencing swap usage or major page faults
- **Classification**: `measured` (Confidence: `high`)
- **Evidence**: `{"pid": 4242, "swap_bytes": 0, "majflt": 1850, "rss_bytes": 536870912}`
- **Likely Causes**: Working set exceeds available physical or cgroup memory
- **Recommended Action**: Tune process memory footprint or increase container memory.max allocation.

### [HIGH] HYP-CGRP-QUOTA: Container CFS quota throttling is actively restricting application threads
- **Classification**: `hypothesis` (Confidence: `high`)
- **Evidence**: `{"cgroup_throttle_pct": 35.0, "host_idle_pct": 3.14}`
- **Likely Causes**: Container CPU quota (cpu.max / cfs_quota_us) is exhausted within 100ms scheduling periods
- **Recommended Action**: Raise container CPU limit or right-size worker thread pool count to match container effective CPUs.

## 2. Subsystem Telemetry Summary

### CPU & Scheduling
- **User / System / Idle / IOWait**: `56.85%` / `22.3%` / `3.14%` / `17.59%` (`cumulative_since_boot`)
- **Context Switches / sec**: `0.0`
- **Run Queue (Running / Blocked)**: `12` / `4`

### Memory
- **Host Memory Used**: `95.0%` (`15938355200` / `16777216000` bytes)
- **Swap Used**: `75.0%`

### Container / Cgroup (`v2`)
- **CPU Quota / Throttle %**: `0.5` CPUs / `35.0%` throttled
- **Cgroup Memory Utilization**: `90.0%`
- **Per-Cgroup PSI**: `{"cpu": {"some": {"avg10": 38.5, "avg60": 29.1, "avg300": 18.0, "total": 7400000.0}, "full": {"avg10": 21.2, "avg60": 15.4, "avg300": 9.1, "total": 3900000.0}}, "memory": {"some": {"avg10": 24.0, "avg60": 18.2, "avg300": 9.5, "total": 3100000.0}, "full": {"avg10": 11.8, "avg60": 7.4, "avg300": 3.2, "total": 1450000.0}}, "io": {"some": {"avg10": 49.0, "avg60": 35.0, "avg300": 22.0, "total": 9200000.0}, "full": {"avg10": 31.4, "avg60": 24.1, "avg300": 14.0, "total": 6100000.0}}}`

### Network
- **TCP States**: `{"ESTABLISHED": 0, "SYN_SENT": 0, "SYN_RECV": 0, "FIN_WAIT1": 0, "FIN_WAIT2": 0, "TIME_WAIT": 0, "CLOSE": 0, "CLOSE_WAIT": 65, "LAST_ACK": 0, "LISTEN": 0, "CLOSING": 0}`
- **TCP Retransmission %**: `2.3%`
- **Queued Sockets**: `65`

### Process Analysis
- **Process Summary**: `{"metric_semantics": {"cpu_pct": "cumulative_snapshot", "memory_rss_and_fds": "instantaneous", "io_and_context_switches": "cumulative_since_process_start"}, "pid": 4242, "comm": "order-worker", "state": "D", "ppid": 1, "threads": 32, "cpu": {"user_pct": 0.0, "system_pct": 0.0, "total_pct": 0.0, "cumulative_utime_ticks": 45000, "cumulative_stime_ticks": 22000}, "memory": {"rss_bytes": 536870912, "v`

## 3. Recommended Next Diagnostic Actions

- Identify top CPU threads via collect_process_metrics.py and verify whether CPU time is user-space or kernel-space.
- Execute scripts/inspect_io.sh to correlate iowait with specific block devices.
- Audit high-RSS processes and check cgroup memory events for OOM risk.
- Correlate /proc/vmstat oom_kill with container cgroup memory.events.
- Align application thread pool size with effective cgroup CPU quota or raise CPU limits.
- Set language runtime memory limits to 80-85% of container memory limit to prevent kernel OOM kills.
- Investigate cgroup-level PSI stalls in memory.pressure and io.pressure.
- Fix application socket leak indicated by elevated CLOSE_WAIT connections.
- Investigate network path packet loss driving TCP retransmissions.
- Remediate TCP accept queue saturation indicated by TcpExt.ListenOverflows.
- Check backing storage latency for D-state process.
- Right-size application worker threads to reduce run-queue wait time and involuntary context switches.
