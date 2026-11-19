#!/usr/bin/env python3
"""Passive host and system-level Linux performance telemetry collector."""
import argparse
import json
import os
import platform
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


def parse_proc_stat(proc_root: Path) -> Dict[str, Any]:
    stat_file = proc_root / "stat"
    result: Dict[str, Any] = {"cpu_total": {}, "ctxt": 0, "procs_running": 0, "procs_blocked": 0, "processes": 0}
    if not stat_file.exists():
        return result
    for line in stat_file.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.split()
        if not parts:
            continue
        if parts[0] == "cpu" and len(parts) >= 9:
            vals = [int(x) for x in parts[1:11]]
            keys = ["user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal", "guest", "guest_nice"]
            result["cpu_total"] = dict(zip(keys[:len(vals)], vals))
        elif parts[0] == "ctxt" and len(parts) >= 2:
            result["ctxt"] = int(parts[1])
        elif parts[0] == "procs_running" and len(parts) >= 2:
            result["procs_running"] = int(parts[1])
        elif parts[0] == "procs_blocked" and len(parts) >= 2:
            result["procs_blocked"] = int(parts[1])
        elif parts[0] == "processes" and len(parts) >= 2:
            result["processes"] = int(parts[1])
    return result


def compute_cpu_deltas(s1: Dict[str, Any], s2: Dict[str, Any], elapsed: float) -> Dict[str, Any]:
    c1 = s1.get("cpu_total", {})
    c2 = s2.get("cpu_total", {})
    if not c1 or not c2:
        return {}
    deltas = {k: max(0, c2.get(k, 0) - c1.get(k, 0)) for k in c1}
    total = sum(deltas.get(k, 0) for k in ["user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal"])
    if total <= 0:
        # Fallback to cumulative tick ratios when single-sample snapshot is taken (samples=1 or interval=0)
        cum_total = sum(c2.get(k, 0) for k in ["user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal"])
        if cum_total <= 0:
            return {"user_pct": 0.0, "system_pct": 0.0, "idle_pct": 100.0, "iowait_pct": 0.0, "steal_pct": 0.0, "ctxt_per_sec": 0.0, "semantics": "empty"}
        return {
            "user_pct": round((c2.get("user", 0) + c2.get("nice", 0)) * 100.0 / cum_total, 2),
            "system_pct": round((c2.get("system", 0) + c2.get("irq", 0) + c2.get("softirq", 0)) * 100.0 / cum_total, 2),
            "idle_pct": round(c2.get("idle", 0) * 100.0 / cum_total, 2),
            "iowait_pct": round(c2.get("iowait", 0) * 100.0 / cum_total, 2),
            "steal_pct": round(c2.get("steal", 0) * 100.0 / cum_total, 2),
            "ctxt_per_sec": 0.0,
            "semantics": "cumulative_since_boot",
        }
    ctxt_delta = max(0, s2.get("ctxt", 0) - s1.get("ctxt", 0))
    return {
        "user_pct": round((deltas.get("user", 0) + deltas.get("nice", 0)) * 100.0 / total, 2),
        "system_pct": round((deltas.get("system", 0) + deltas.get("irq", 0) + deltas.get("softirq", 0)) * 100.0 / total, 2),
        "idle_pct": round(deltas.get("idle", 0) * 100.0 / total, 2),
        "iowait_pct": round(deltas.get("iowait", 0) * 100.0 / total, 2),
        "steal_pct": round(deltas.get("steal", 0) * 100.0 / total, 2),
        "ctxt_per_sec": round(ctxt_delta / max(elapsed, 0.001), 2),
        "semantics": "interval_derived",
    }


def parse_meminfo(proc_root: Path) -> Dict[str, int]:
    mem_file = proc_root / "meminfo"
    info: Dict[str, int] = {}
    if not mem_file.exists():
        return info
    for line in mem_file.read_text(encoding="utf-8", errors="replace").splitlines():
        if ":" not in line:
            continue
        k, rest = line.split(":", 1)
        parts = rest.strip().split()
        if parts and parts[0].isdigit():
            info[k.strip()] = int(parts[0]) * 1024
    return info


def parse_loadavg(proc_root: Path) -> Dict[str, Any]:
    lf = proc_root / "loadavg"
    if not lf.exists():
        return {}
    parts = lf.read_text(encoding="utf-8", errors="replace").strip().split()
    if len(parts) < 4:
        return {}
    return {
        "load_1m": float(parts[0]),
        "load_5m": float(parts[1]),
        "load_15m": float(parts[2]),
        "scheduling_entities": parts[3],
    }


def parse_psi(proc_root: Path) -> Dict[str, Any]:
    psi_dir = proc_root / "pressure"
    psi_data: Dict[str, Any] = {}
    if not psi_dir.exists():
        return psi_data
    for resource in ("cpu", "memory", "io"):
        f = psi_dir / resource
        if not f.exists():
            continue
        try:
            res_entry: Dict[str, Dict[str, float]] = {}
            for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
                parts = line.strip().split()
                if not parts:
                    continue
                kind = parts[0]
                kv = {}
                for token in parts[1:]:
                    if "=" in token:
                        k, v = token.split("=", 1)
                        try:
                            kv[k] = float(v)
                        except ValueError:
                            pass
                res_entry[kind] = kv
            psi_data[resource] = res_entry
        except Exception:
            continue
    return psi_data


def parse_vmstat_oom(proc_root: Path) -> Dict[str, int]:
    vf = proc_root / "vmstat"
    out: Dict[str, int] = {}
    if not vf.exists():
        return out
    keys = {"oom_kill", "pswpin", "pswpout", "pgmajfault", "pgfault"}
    for line in vf.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.strip().split()
        if len(parts) == 2 and parts[0] in keys and parts[1].isdigit():
            out[parts[0]] = int(parts[1])
    return out


def collect_system_metrics(proc_root: Path, interval: float = 0.2, samples: int = 2) -> Dict[str, Any]:
    warnings: List[str] = []
    errors: List[str] = []
    findings: List[Dict[str, Any]] = []
    recommendations: List[str] = []

    if not proc_root.exists():
        return {
            "status": "error",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "platform": {"system": platform.system(), "release": platform.release()},
            "tool_versions": {"python": platform.python_version()},
            "findings": [],
            "metrics": {},
            "warnings": [],
            "recommendations": [],
            "errors": [f"Proc root does not exist: {proc_root}"],
        }

    s1 = parse_proc_stat(proc_root)
    actual_elapsed = 0.0
    if samples > 1 and interval > 0:
        t0 = time.monotonic()
        time.sleep(min(interval, 10.0))
        actual_elapsed = time.monotonic() - t0
        s2 = parse_proc_stat(proc_root)
    else:
        s2 = s1

    cpu_summary = compute_cpu_deltas(s1, s2, actual_elapsed if actual_elapsed > 0 else 1.0)
    mem = parse_meminfo(proc_root)
    loadavg = parse_loadavg(proc_root)
    psi = parse_psi(proc_root)
    vmstat = parse_vmstat_oom(proc_root)
    cpu_count = os.cpu_count() or 1

    mem_total = mem.get("MemTotal", 0)
    mem_avail = mem.get("MemAvailable", mem.get("MemFree", 0))
    mem_used = max(0, mem_total - mem_avail)
    mem_used_pct = round((mem_used * 100.0 / mem_total), 2) if mem_total > 0 else 0.0

    swap_total = mem.get("SwapTotal", 0)
    swap_free = mem.get("SwapFree", 0)
    swap_used = max(0, swap_total - swap_free)
    swap_used_pct = round((swap_used * 100.0 / swap_total), 2) if swap_total > 0 else 0.0

    status = "ok"

    busy_pct = round(100.0 - cpu_summary.get("idle_pct", 100.0), 2) if cpu_summary else 0.0
    if busy_pct >= 85.0:
        status = "warning" if busy_pct < 95.0 else "critical"
        findings.append({
            "id": "SYS-CPU-001",
            "category": "cpu",
            "severity": "high" if busy_pct >= 95.0 else "medium",
            "classification": "measured",
            "title": f"High CPU utilization detected ({busy_pct}% busy)",
            "evidence": {
                "busy_pct": busy_pct,
                "user_pct": cpu_summary.get("user_pct"),
                "system_pct": cpu_summary.get("system_pct"),
                "procs_running": s2.get("procs_running"),
                "cpu_count": cpu_count,
                "semantics": cpu_summary.get("semantics"),
            },
            "likely_causes": [
                "Compute-bound worker loops or serialization overhead" if cpu_summary.get("user_pct", 0) >= cpu_summary.get("system_pct", 0)
                else "High kernel syscall rate, lock contention, or aggressive network/disk interrupt handling"
            ],
            "confidence": "high",
            "recommendation": "Inspect top CPU-consuming PIDs with scripts/collect_process_metrics.py and check cgroup throttling."
        })
        recommendations.append("Identify top CPU threads via collect_process_metrics.py and verify whether CPU time is user-space or kernel-space.")

    iowait_pct = cpu_summary.get("iowait_pct", 0.0)
    if iowait_pct >= 15.0 or s2.get("procs_blocked", 0) >= 2:
        if status == "ok":
            status = "warning"
        findings.append({
            "id": "SYS-IO-001",
            "category": "io",
            "severity": "medium" if iowait_pct < 35.0 else "high",
            "classification": "measured",
            "title": f"Elevated I/O wait ({iowait_pct}%) or blocked tasks ({s2.get('procs_blocked', 0)})",
            "evidence": {
                "iowait_pct": iowait_pct,
                "procs_blocked": s2.get("procs_blocked", 0),
                "psi_io": psi.get("io", {}),
            },
            "likely_causes": [
                "Synchronous disk writes (fsync/fdatasync) saturating backing storage",
                "Memory pressure causing major page faults and swap I/O"
            ],
            "confidence": "high",
            "recommendation": "Run scripts/inspect_io.sh to inspect per-device await/utilization and identify uninterruptible sleep (D-state) processes."
        })
        recommendations.append("Execute scripts/inspect_io.sh to correlate iowait with specific block devices.")

    if mem_used_pct >= 85.0:
        status = "critical" if mem_used_pct >= 95.0 else ("warning" if status == "ok" else status)
        findings.append({
            "id": "SYS-MEM-001",
            "category": "memory",
            "severity": "high" if mem_used_pct >= 95.0 else "medium",
            "classification": "measured",
            "title": f"High system memory utilization ({mem_used_pct}% used)",
            "evidence": {
                "mem_total_bytes": mem_total,
                "mem_available_bytes": mem_avail,
                "mem_used_pct": mem_used_pct,
                "swap_used_pct": swap_used_pct,
            },
            "likely_causes": [
                "Unbounded application heap or cache growth",
                "Insufficient container or VM memory allocation relative to worker concurrency"
            ],
            "confidence": "high",
            "recommendation": "Check process RSS growth using scripts/collect_process_metrics.py and verify cgroup memory.max limits."
        })
        recommendations.append("Audit high-RSS processes and check cgroup memory events for OOM risk.")

    oom_kills = vmstat.get("oom_kill", 0)
    if oom_kills > 0:
        if status == "ok":
            status = "warning"
        findings.append({
            "id": "SYS-MEM-002",
            "category": "memory",
            "severity": "high",
            "classification": "measured",
            "title": f"Kernel OOM killer invocations recorded (oom_kill={oom_kills})",
            "evidence": {"vmstat_oom_kill": oom_kills, "pgmajfault": vmstat.get("pgmajfault", 0)},
            "likely_causes": ["Host or cgroup memory exhaustion triggering Linux OOM killer"],
            "confidence": "high",
            "recommendation": "Inspect cgroup memory.events for oom_kill counters and set bounded heap limits on worker processes."
        })
        recommendations.append("Correlate /proc/vmstat oom_kill with container cgroup memory.events.")

    if not findings:
        findings.append({
            "id": "SYS-OK-001",
            "category": "system",
            "severity": "info",
            "classification": "measured",
            "title": "Host CPU, memory, and I/O baseline within normal operating thresholds",
            "evidence": {
                "busy_pct": busy_pct,
                "mem_used_pct": mem_used_pct,
                "iowait_pct": iowait_pct,
                "load_1m": loadavg.get("load_1m"),
            },
            "likely_causes": ["No host-wide saturation observed during sampling window"],
            "confidence": "high",
            "recommendation": "If latency persists, inspect per-process or container-specific cgroup constraints."
        })

    return {
        "status": status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "cpu_count": cpu_count,
        },
        "tool_versions": {"python": platform.python_version()},
        "findings": findings,
        "metrics": {
            "metric_semantics": {
                "cpu": cpu_summary.get("semantics", "interval_derived"),
                "memory_and_scheduling": "instantaneous",
                "vmstat_counters": "cumulative_since_boot",
                "psi": "rolling_window_average_pct",
            },
            "cpu": cpu_summary,
            "scheduling": {
                "procs_running": s2.get("procs_running", 0),
                "procs_blocked": s2.get("procs_blocked", 0),
                "total_forks": s2.get("processes", 0),
                "loadavg": loadavg,
            },
            "memory": {
                "mem_total_bytes": mem_total,
                "mem_available_bytes": mem_avail,
                "mem_used_bytes": mem_used,
                "mem_used_pct": mem_used_pct,
                "swap_total_bytes": swap_total,
                "swap_used_bytes": swap_used,
                "swap_used_pct": swap_used_pct,
                "buffers_bytes": mem.get("Buffers", 0),
                "cached_bytes": mem.get("Cached", 0),
            },
            "vmstat": vmstat,
            "psi": psi,
        },
        "warnings": warnings,
        "recommendations": recommendations or ["Host baseline healthy."],
        "errors": errors,
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Collect passive Linux system telemetry.")
    parser.add_argument("--proc-root", default="/proc", help="Path to /proc filesystem (or fixture directory)")
    parser.add_argument("--interval", type=float, default=0.2, help="Sampling interval in seconds (0 to 60)")
    parser.add_argument("--samples", type=int, default=2, help="Number of stat samples (1 to 10)")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")
    args = parser.parse_args(argv)

    if args.interval < 0 or args.interval > 60:
        err = {
            "status": "error",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "platform": {},
            "tool_versions": {},
            "findings": [],
            "metrics": {},
            "warnings": [],
            "recommendations": [],
            "errors": ["Interval must be between 0 and 60 seconds"],
        }
        print(json.dumps(err), file=sys.stderr)
        return 2
    if args.samples < 1 or args.samples > 10:
        err = {
            "status": "error",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "platform": {},
            "tool_versions": {},
            "findings": [],
            "metrics": {},
            "warnings": [],
            "recommendations": [],
            "errors": ["Samples must be between 1 and 10"],
        }
        print(json.dumps(err), file=sys.stderr)
        return 2

    payload = collect_system_metrics(Path(args.proc_root), args.interval, args.samples)
    if payload["status"] == "error":
        print(json.dumps(payload), file=sys.stderr)
        return 1
    print(json.dumps(payload, indent=2 if args.pretty else None))
    return 0


if __name__ == "__main__":
    sys.exit(main())
