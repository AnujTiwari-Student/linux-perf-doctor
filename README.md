# linux-perf-doctor

<p align="center">
  <img src="assets/branding/logo.svg" alt="linux-perf-doctor logo" width="180" />
</p>


**Read-only Linux Performance Diagnostics for AI Agents and SRE Workflows**

## 1. Project Name and Positioning
`linux-perf-doctor` is a production-grade [Agent Skill](https://agentskills.io/specification) that equips AI coding and SRE agents with deterministic Linux operating-system telemetry collection, cgroup v1/v2 container pressure analysis, and evidence-backed bottleneck diagnosis.

## 2. Problem Statement
When applications suffer latency spikes, CPU throttling, or OOM terminations in production or containerized staging environments, AI coding assistants frequently speculate about source-code algorithms without inspecting actual kernel counters. Furthermore, containerized workloads often misreport host `/proc/meminfo` and CPU core counts while silently suffering cgroup CFS bandwidth throttling (`nr_throttled`) or cgroup memory reclaim stalls.

## 3. What the Skill Actually Does
`linux-perf-doctor` executes deterministic, read-only collectors against `/proc`, `/sys/fs/cgroup`, `/proc/pressure` (PSI), `/proc/diskstats`, and `/proc/net/tcp*`, with optional capability detection for `perf`, `strace`, `ss`, `iostat`, `vmstat`, `pidstat`, and eBPF utilities. It correlates findings across subsystems and distinguishes **measured facts** from **diagnostic hypotheses**.

## 4. Key Features
- **Capability & Security Guard Detection**: Checks installed binaries (`perf`, `strace`, `ss`, `iostat`, `vmstat`, `bpftool`) and kernel security parameters (`perf_event_paranoid`, `yama.ptrace_scope`, `kptr_restrict`).
- **System & PSI Telemetry**: Measures CPU user/system/idle/iowait/steal deltas, context switch rates, `/proc/vmstat` OOM/fault counters, and Linux Pressure Stall Information (`cpu`, `memory`, `io`).
- **Container & Cgroup v1/v2 Analyzer**: Detects CFS quota throttling (`nr_throttled`, `throttled_usec`), `memory.current` vs `memory.max`, and `memory.events` (`oom_kill`, `high` reclaim stalls).
- **Targeted Process Inspector**: Analyzes per-PID CPU ticks, RSS/Swap, major page faults, voluntary vs involuntary context switches, open file descriptors, and `/proc/<pid>/io`.
- **Network & Block I/O Diagnostics**: Identifies `CLOSE_WAIT` socket leaks, `TIME_WAIT` churn, `SYN_RECV` backlog saturation, non-zero `Recv-Q`/`Send-Q` buffers, and high block-device `await` latencies.
- **Strictly Opt-In Active Profiling**: Requires `--enable-active-profiling` before invoking `strace` or `perf` with bounded duration timeouts.

### Project Demo

Watch Linux Perf Doctor in action:

[**Watch the demonstration on LinkedIn →**](https://lnkd.in/p/dRXQRwFk)


## 5. Architecture Overview
See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the complete four-stage pipeline:
1. `scripts/check_perf_capabilities.sh` -> Capability & permission discovery
2. `scripts/collect_system_metrics.py`, `scripts/collect_process_metrics.py`, `scripts/inspect_cgroups.py`, `scripts/inspect_io.sh`, `scripts/inspect_network.py` -> Passive telemetry collection
3. `scripts/profile_process.sh` -> Opt-in active profiling (`passive-summary`, `strace-summary`, `perf-stat`)
4. `scripts/generate_report.py` -> Cross-subsystem correlation & JSON/Markdown report synthesis

## 6. Installation

### Install directly from GitHub (Recommended)

Install the skill from its public repository:

```bash
npx skills add AnujTiwari-Student/linux-perf-doctor --skill linux-perf-doctor
```

To install the published v1.0.0 release specifically:

```bash
npx skills add AnujTiwari-Student/linux-perf-doctor@v1.0.0 --skill linux-perf-doctor
```

### Install from a Local Clone

Clone the repository and install from its root directory:

```bash
# Download the source from GitHub (Code > Download ZIP) and extract it
cd <extracted-directory>
npx skills add . --skill linux-perf-doctor
```

### Manual Installation

Run these commands from the parent directory containing `linux-perf-doctor/`.

For Claude Code:

```bash
mkdir -p ~/.claude/skills
cp -r ./linux-perf-doctor ~/.claude/skills/linux-perf-doctor
```

For OpenAI Codex:

```bash
mkdir -p ~/.agents/skills
cp -r ./linux-perf-doctor ~/.agents/skills/linux-perf-doctor
```

## 7. Supported Agent Environments
See [`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md) for detailed verification classifications across Claude Code, OpenAI Codex, Gemini CLI, Google Antigravity, OpenCode, and Hermes Agent.

## 8. Prerequisites
- Linux kernel with `/proc` and `/sys` mounted (supports both host nodes and unprivileged containers).
- Python 3.8+ (standard library only; zero external PyPI packages required).
- GNU Bash 4.0+.
- Optional CLI tools (`perf`, `strace`, `ss`, `iostat`, `vmstat`, `pidstat`, `bpftool`) are auto-detected and gracefully skipped if absent.

## 9. Usage Examples
Ask your AI agent:
- *"Use `linux-perf-doctor` to check why our container is experiencing tail latency spikes despite low node CPU."*
- *"Inspect PID 4242 with `linux-perf-doctor` and generate a Markdown bottleneck report."*

## 10. Script Examples
```bash
# 1. Check host capabilities and kernel guards
./scripts/check_perf_capabilities.sh --pretty

# 2. Collect host system metrics across two 200ms intervals
python3 scripts/collect_system_metrics.py --interval 0.2 --samples 2 --pretty

# 3. Inspect container cgroup v1/v2 throttling and memory events
python3 scripts/inspect_cgroups.py --cgroup-root /sys/fs/cgroup --pretty

# 4. Generate a unified Markdown diagnostic report
python3 scripts/generate_report.py --format markdown --output examples/live-host-report.md
```

## 11. Example Diagnostic Results
See [`examples/sample-saturated-report.md`](examples/sample-saturated-report.md) and [`examples/sample-saturated-report.json`](examples/sample-saturated-report.json) for complete outputs generated from the saturated container/node fixture (`tests/fixtures/saturated_node`).

## 12. Security and Safety Approach
- Read-only passive inspection by default.
- Never invokes privilege-escalation wrappers or modifies kernel parameters.
- Never reads `/proc/<pid>/environ` or prints secrets.
- Active profilers (`strace`, `perf`) are blocked unless `--enable-active-profiling` is explicitly passed. See [`docs/SECURITY.md`](docs/SECURITY.md).

## 13. Limitations
- On macOS or Windows hosts without a Linux `/proc` filesystem, live host collection returns a clean error unless pointed at a captured `/proc` snapshot directory via `--proc-root`.
- Unprivileged users cannot read `/proc/<pid>/io` or `/proc/<pid>/fd` for processes owned by other UIDs; the collector logs a warning and continues with `/proc/<pid>/stat` and `/proc/<pid>/status`.

## 14. Testing Instructions
```bash
python3 -m unittest discover -s tests -v
```

## 15. Contribution Instructions
See [`CONTRIBUTING.md`](CONTRIBUTING.md) for code style, stdlib-only rules, and test requirements.

## 16. Roadmap
- Add optional `bpftool` / `bpftrace` read-only map dump parsers when running with `CAP_BPF`.
- Add `/proc/slabinfo` kernel slab cache pressure analysis.

## 17. License
MIT License. See [`LICENSE`](LICENSE).
