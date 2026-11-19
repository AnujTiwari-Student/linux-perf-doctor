#!/usr/bin/env python3
"""Inspect cgroup v1 and v2 CPU throttling, memory pressure, OOM events, and per-cgroup PSI."""
import argparse
import json
import os
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


def read_text_safe(p: Path) -> Optional[str]:
    try:
        if p.exists():
            return p.read_text(encoding="utf-8", errors="replace").strip()
    except Exception:
        pass
    return None


def parse_kv_lines(raw: Optional[str]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    if not raw:
        return out
    for line in raw.splitlines():
        parts = line.strip().split()
        if len(parts) == 2 and parts[1].lstrip("-").isdigit():
            out[parts[0]] = int(parts[1])
    return out


def parse_psi_file(p: Path) -> Dict[str, Dict[str, float]]:
    raw = read_text_safe(p)
    out: Dict[str, Dict[str, float]] = {}
    if not raw:
        return out
    for line in raw.splitlines():
        parts = line.strip().split()
        if not parts:
            continue
        kind = parts[0]
        kv: Dict[str, float] = {}
        for tok in parts[1:]:
            if "=" in tok:
                k, v = tok.split("=", 1)
                try:
                    kv[k] = float(v)
                except ValueError:
                    pass
        out[kind] = kv
    return out


def inspect_cgroups(cgroup_root: Path) -> Dict[str, Any]:
    warnings: List[str] = []
    errors: List[str] = []
    findings: List[Dict[str, Any]] = []
    recommendations: List[str] = []

    if not cgroup_root.exists():
        return {
            "status": "error",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "platform": {"system": platform.system(), "release": platform.release()},
            "tool_versions": {"python": platform.python_version()},
            "findings": [],
            "metrics": {},
            "warnings": [],
            "recommendations": [],
            "errors": [f"Cgroup root does not exist: {cgroup_root}"],
        }

    is_v2 = (
        (cgroup_root / "cgroup.controllers").exists()
        or (cgroup_root / "cpu.stat").exists()
        or (cgroup_root / "memory.current").exists()
    )
    metrics: Dict[str, Any] = {
        "metric_semantics": {
            "memory_current_and_pids": "instantaneous",
            "cpu_stat_and_memory_events": "cumulative_since_cgroup_creation",
            "pressure_avg10_60_300": "rolling_window_average_pct",
        },
        "cgroup_version": "v2" if is_v2 else "v1",
        "cpu": {},
        "memory": {},
        "pids": {},
        "pressure": {},
    }
    status = "ok"

    if is_v2:
        cpu_max_raw = read_text_safe(cgroup_root / "cpu.max")
        cpu_stat = parse_kv_lines(read_text_safe(cgroup_root / "cpu.stat"))
        mem_current_raw = read_text_safe(cgroup_root / "memory.current")
        mem_max_raw = read_text_safe(cgroup_root / "memory.max")
        mem_events = parse_kv_lines(read_text_safe(cgroup_root / "memory.events"))
        pids_current_raw = read_text_safe(cgroup_root / "pids.current")
        pids_max_raw = read_text_safe(cgroup_root / "pids.max")

        for res in ("cpu", "memory", "io"):
            psi_path = cgroup_root / f"{res}.pressure"
            if psi_path.exists():
                metrics["pressure"][res] = parse_psi_file(psi_path)

        quota_us = None
        period_us = 100000
        if cpu_max_raw:
            parts = cpu_max_raw.split()
            if parts[0] != "max" and parts[0].isdigit():
                quota_us = int(parts[0])
            if len(parts) > 1 and parts[1].isdigit():
                period_us = int(parts[1])

        nr_periods = cpu_stat.get("nr_periods", 0)
        nr_throttled = cpu_stat.get("nr_throttled", 0)
        throttled_usec = cpu_stat.get("throttled_usec", 0)
        throttle_pct = round((nr_throttled * 100.0 / nr_periods), 2) if nr_periods > 0 else 0.0

        metrics["cpu"] = {
            "cpu_max_raw": cpu_max_raw,
            "quota_us": quota_us,
            "period_us": period_us,
            "effective_cpus": round(quota_us / period_us, 2) if quota_us else "unlimited",
            "nr_periods": nr_periods,
            "nr_throttled": nr_throttled,
            "throttled_usec": throttled_usec,
            "throttle_pct": throttle_pct,
        }

        mem_current = int(mem_current_raw) if (mem_current_raw and mem_current_raw.isdigit()) else None
        mem_max = int(mem_max_raw) if (mem_max_raw and mem_max_raw.isdigit()) else None
        mem_pct = round((mem_current * 100.0 / mem_max), 2) if (mem_current is not None and mem_max and mem_max > 0) else None

        metrics["memory"] = {
            "current_bytes": mem_current,
            "max_bytes": mem_max if mem_max is not None else "max",
            "utilization_pct": mem_pct,
            "events": mem_events,
        }
        metrics["pids"] = {
            "current": int(pids_current_raw) if (pids_current_raw and pids_current_raw.isdigit()) else None,
            "max": int(pids_max_raw) if (pids_max_raw and pids_max_raw.isdigit()) else (pids_max_raw or "max"),
        }
    else:
        # cgroup v1 controller discovery (supports both /sys/fs/cgroup/{cpu,memory,pids} and flat hierarchy)
        cpu_dir = cgroup_root / "cpu" if (cgroup_root / "cpu").exists() else cgroup_root
        mem_dir = cgroup_root / "memory" if (cgroup_root / "memory").exists() else cgroup_root
        pids_dir = cgroup_root / "pids" if (cgroup_root / "pids").exists() else cgroup_root

        quota_raw = read_text_safe(cpu_dir / "cpu.cfs_quota_us")
        period_raw = read_text_safe(cpu_dir / "cpu.cfs_period_us")
        cpu_stat = parse_kv_lines(read_text_safe(cpu_dir / "cpu.stat"))
        mem_usage_raw = read_text_safe(mem_dir / "memory.usage_in_bytes")
        mem_limit_raw = read_text_safe(mem_dir / "memory.limit_in_bytes")
        mem_failcnt_raw = read_text_safe(mem_dir / "memory.failcnt")
        oom_ctrl = parse_kv_lines(read_text_safe(mem_dir / "memory.oom_control"))
        pids_cur_raw = read_text_safe(pids_dir / "pids.current")
        pids_max_raw = read_text_safe(pids_dir / "pids.max")

        nr_periods = cpu_stat.get("nr_periods", 0)
        nr_throttled = cpu_stat.get("nr_throttled", 0)
        throttle_pct = round((nr_throttled * 100.0 / nr_periods), 2) if nr_periods > 0 else 0.0
        quota_val = int(quota_raw) if (quota_raw and quota_raw.lstrip("-").isdigit()) else None
        period_val = int(period_raw) if (period_raw and period_raw.isdigit()) else 100000
        effective_cpus = round(quota_val / period_val, 2) if (quota_val and quota_val > 0) else "unlimited"

        metrics["cpu"] = {
            "cfs_quota_us": quota_val,
            "cfs_period_us": period_val,
            "effective_cpus": effective_cpus,
            "nr_periods": nr_periods,
            "nr_throttled": nr_throttled,
            "throttled_time_ns": cpu_stat.get("throttled_time", 0),
            "throttle_pct": throttle_pct,
        }
        mem_current = int(mem_usage_raw) if (mem_usage_raw and mem_usage_raw.isdigit()) else None
        mem_max = int(mem_limit_raw) if (mem_limit_raw and mem_limit_raw.isdigit() and int(mem_limit_raw) < (1 << 60)) else None
        mem_pct = round((mem_current * 100.0 / mem_max), 2) if (mem_current is not None and mem_max) else None
        failcnt = int(mem_failcnt_raw) if (mem_failcnt_raw and mem_failcnt_raw.isdigit()) else 0
        oom_kill_v1 = oom_ctrl.get("oom_kill", 0)

        metrics["memory"] = {
            "current_bytes": mem_current,
            "max_bytes": mem_max if mem_max is not None else "unlimited",
            "utilization_pct": mem_pct,
            "failcnt": failcnt,
            "events": {"oom_kill": oom_kill_v1, "under_oom": oom_ctrl.get("under_oom", 0), "high": failcnt},
        }
        metrics["pids"] = {
            "current": int(pids_cur_raw) if (pids_cur_raw and pids_cur_raw.isdigit()) else None,
            "max": int(pids_max_raw) if (pids_max_raw and pids_max_raw.isdigit()) else (pids_max_raw or "max"),
        }

    # Analyze findings
    throttle_pct = metrics["cpu"].get("throttle_pct", 0.0)
    if throttle_pct >= 5.0 or metrics["cpu"].get("nr_throttled", 0) >= 50:
        status = "warning" if throttle_pct < 25.0 else "critical"
        findings.append({
            "id": "CGRP-CPU-001",
            "category": "cgroup_cpu",
            "severity": "high" if throttle_pct >= 25.0 else "medium",
            "classification": "measured",
            "title": f"Container CFS CPU throttling detected ({throttle_pct}% of periods throttled)",
            "evidence": metrics["cpu"],
            "likely_causes": [
                "Multi-threaded application bursting above container CPU quota within 100ms period",
                "Restrictive Kubernetes/Docker CPU limit relative to worker thread count"
            ],
            "confidence": "high",
            "recommendation": "Increase container CPU limit or tune runtime worker threads (e.g., GOMAXPROCS, UV_THREADPOOL_SIZE) to match effective CPU quota."
        })
        recommendations.append("Align application thread pool size with effective cgroup CPU quota or raise CPU limits.")

    mem_pct = metrics["memory"].get("utilization_pct")
    mem_events = metrics["memory"].get("events", {})
    oom_kills = mem_events.get("oom_kill", 0)
    oom_events = mem_events.get("oom", 0) + mem_events.get("under_oom", 0)
    high_events = mem_events.get("high", 0)

    if oom_kills > 0 or oom_events > 0:
        status = "critical"
        findings.append({
            "id": "CGRP-MEM-001",
            "category": "cgroup_memory",
            "severity": "critical",
            "classification": "measured",
            "title": f"Cgroup OOM events recorded (oom_kill={oom_kills}, oom={oom_events})",
            "evidence": metrics["memory"],
            "likely_causes": ["Container memory working set exceeded cgroup memory limit"],
            "confidence": "high",
            "recommendation": "Increase container memory limit or configure runtime heap bounds (e.g., NODE_OPTIONS=--max-old-space-size, GOMEMLIMIT) below cgroup memory ceiling."
        })
        recommendations.append("Set language runtime memory limits to 80-85% of container memory limit to prevent kernel OOM kills.")
    elif (mem_pct is not None and mem_pct >= 85.0) or high_events > 0:
        if status == "ok":
            status = "warning"
        findings.append({
            "id": "CGRP-MEM-002",
            "category": "cgroup_memory",
            "severity": "medium",
            "classification": "measured",
            "title": f"Elevated cgroup memory pressure (utilization={mem_pct}%, throttle/failcnt events={high_events})",
            "evidence": metrics["memory"],
            "likely_causes": ["Container approaching memory ceiling, triggering direct reclaim"],
            "confidence": "high",
            "recommendation": "Monitor process RSS and review cgroup memory sizing."
        })

    # Per-cgroup PSI checks
    psi_mem_full = metrics["pressure"].get("memory", {}).get("full", {}).get("avg10", 0.0)
    psi_io_full = metrics["pressure"].get("io", {}).get("full", {}).get("avg10", 0.0)
    if psi_mem_full >= 5.0 or psi_io_full >= 10.0:
        if status == "ok":
            status = "warning"
        findings.append({
            "id": "CGRP-PSI-001",
            "category": "cgroup_psi",
            "severity": "high" if (psi_mem_full >= 15.0 or psi_io_full >= 25.0) else "medium",
            "classification": "measured",
            "title": f"Elevated per-cgroup Pressure Stall Information (memory full avg10={psi_mem_full}%, io full avg10={psi_io_full}%)",
            "evidence": metrics["pressure"],
            "likely_causes": ["Cgroup tasks stalled on direct memory reclaim or cgroup I/O throttling"],
            "confidence": "high",
            "recommendation": "Inspect cgroup memory.high/memory.max and io.max limits."
        })
        recommendations.append("Investigate cgroup-level PSI stalls in memory.pressure and io.pressure.")

    if not findings:
        findings.append({
            "id": "CGRP-OK-001",
            "category": "cgroup",
            "severity": "info",
            "classification": "measured",
            "title": f"Cgroup ({metrics['cgroup_version']}) limits and throttling counters healthy",
            "evidence": {"cpu": metrics["cpu"], "memory": metrics["memory"]},
            "likely_causes": ["No active container CPU throttling or memory OOM pressure"],
            "confidence": "high",
            "recommendation": "No immediate cgroup limit adjustments required."
        })

    return {
        "status": status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "platform": {"system": platform.system(), "release": platform.release()},
        "tool_versions": {"python": platform.python_version()},
        "findings": findings,
        "metrics": metrics,
        "warnings": warnings,
        "recommendations": recommendations or ["No cgroup adjustments required."],
        "errors": errors,
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Inspect cgroup v1/v2 resource limits and pressure.")
    parser.add_argument("--cgroup-root", default="/sys/fs/cgroup", help="Path to cgroup root directory")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")
    args = parser.parse_args(argv)

    payload = inspect_cgroups(Path(args.cgroup_root))
    if payload["status"] == "error":
        print(json.dumps(payload), file=sys.stderr)
        return 1
    print(json.dumps(payload, indent=2 if args.pretty else None))
    return 0


if __name__ == "__main__":
    sys.exit(main())
