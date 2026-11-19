#!/usr/bin/env python3
"""Targeted process-level telemetry collector using /proc/[pid]/stat, status, io, fd, and sched."""
import argparse
import json
import os
import platform
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def read_proc_stat(pid_dir: Path) -> Optional[Dict[str, Any]]:
    sf = pid_dir / "stat"
    if not sf.exists():
        return None
    try:
        raw = sf.read_text(encoding="utf-8", errors="replace").strip()
        rparen = raw.rfind(")")
        lparen = raw.find("(")
        if lparen == -1 or rparen == -1:
            return None
        comm = raw[lparen + 1:rparen]
        rest = raw[rparen + 2:].split()
        return {
            "pid": int(raw[:lparen].strip()),
            "comm": comm,
            "state": rest[0],
            "ppid": int(rest[1]),
            "minflt": int(rest[7]),
            "majflt": int(rest[9]),
            "utime": int(rest[11]),
            "stime": int(rest[12]),
            "num_threads": int(rest[17]),
            "vsize_bytes": int(rest[20]),
            "rss_pages": int(rest[21]),
        }
    except Exception:
        return None


def read_proc_status(pid_dir: Path) -> Dict[str, Any]:
    st_file = pid_dir / "status"
    out: Dict[str, Any] = {}
    if not st_file.exists():
        return out
    try:
        for line in st_file.read_text(encoding="utf-8", errors="replace").splitlines():
            if ":" not in line:
                continue
            k, v = line.split(":", 1)
            k = k.strip()
            v = v.strip()
            if k in ("VmPeak", "VmSize", "VmRSS", "VmData", "VmSwap"):
                parts = v.split()
                if parts and parts[0].isdigit():
                    out[f"{k}_bytes"] = int(parts[0]) * 1024
            elif k in ("voluntary_ctxt_switches", "nonvoluntary_ctxt_switches", "Threads"):
                if v.isdigit():
                    out[k] = int(v)
            elif k == "State":
                out["state_desc"] = v
            elif k == "CapEff":
                out["cap_eff_hex"] = v
    except Exception:
        pass
    return out


def read_proc_sched(pid_dir: Path) -> Dict[str, Any]:
    """Parse /proc/[pid]/sched scheduler runtime, wait_sum, iowait_sum, and migrations."""
    sched_file = pid_dir / "sched"
    out: Dict[str, Any] = {}
    if not sched_file.exists():
        return out
    keys_of_interest = {
        "se.sum_exec_runtime": "sum_exec_runtime_ms",
        "se.vruntime": "vruntime",
        "se.nr_migrations": "nr_migrations",
        "nr_switches": "nr_switches",
        "nr_voluntary_switches": "nr_voluntary_switches",
        "nr_involuntary_switches": "nr_involuntary_switches",
        "se.statistics.wait_sum": "runqueue_wait_sum_ms",
        "se.statistics.iowait_sum": "iowait_sum_ms",
    }
    try:
        for line in sched_file.read_text(encoding="utf-8", errors="replace").splitlines():
            if ":" not in line:
                continue
            k, v = line.split(":", 1)
            k = k.strip()
            v = v.strip()
            if k in keys_of_interest:
                try:
                    val = float(v) if "." in v else int(v)
                    out[keys_of_interest[k]] = val
                except ValueError:
                    pass
    except Exception:
        pass
    return out


def read_proc_io(pid_dir: Path) -> Tuple[Dict[str, int], Optional[str]]:
    io_file = pid_dir / "io"
    out: Dict[str, int] = {}
    if not io_file.exists():
        return out, None
    try:
        for line in io_file.read_text(encoding="utf-8", errors="replace").splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                v = v.strip()
                if v.isdigit():
                    out[k.strip()] = int(v)
        return out, None
    except PermissionError:
        return {}, "Permission denied reading /proc/<pid>/io (requires process owner or CAP_DAC_READ_SEARCH)."
    except Exception as exc:
        return {}, f"Could not read /proc/<pid>/io: {exc}"


def count_open_fds(pid_dir: Path) -> Tuple[Optional[int], Optional[str]]:
    fd_dir = pid_dir / "fd"
    if not fd_dir.exists():
        return None, None
    try:
        return len(list(fd_dir.iterdir())), None
    except PermissionError:
        return None, "Permission denied listing /proc/<pid>/fd."
    except Exception as exc:
        return None, str(exc)


def inspect_single_pid(proc_root: Path, pid: int, interval: float = 0.2) -> Dict[str, Any]:
    pid_dir = proc_root / str(pid)
    warnings: List[str] = []
    errors: List[str] = []
    findings: List[Dict[str, Any]] = []
    recommendations: List[str] = []

    if not pid_dir.exists():
        return {
            "status": "error",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "platform": {"system": platform.system(), "release": platform.release()},
            "tool_versions": {"python": platform.python_version()},
            "findings": [],
            "metrics": {},
            "warnings": [],
            "recommendations": [],
            "errors": [f"Process PID {pid} not found in {proc_root}"],
        }

    s1 = read_proc_stat(pid_dir)
    if s1 is None:
        return {
            "status": "error",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "platform": {"system": platform.system(), "release": platform.release()},
            "tool_versions": {"python": platform.python_version()},
            "findings": [],
            "metrics": {},
            "warnings": [],
            "recommendations": [],
            "errors": [f"Unable to parse {pid_dir}/stat"],
        }

    clk_tck = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
    page_size = os.sysconf("SC_PAGE_SIZE") if hasattr(os, "sysconf") else 4096

    if interval > 0:
        t0 = time.monotonic()
        time.sleep(min(interval, 10.0))
        elapsed = max(time.monotonic() - t0, 0.001)
        s2 = read_proc_stat(pid_dir) or s1
        cpu_semantics = "interval_derived"
    else:
        elapsed = 1.0
        s2 = s1
        cpu_semantics = "cumulative_snapshot"

    utime_delta = max(0, s2["utime"] - s1["utime"]) / float(clk_tck)
    stime_delta = max(0, s2["stime"] - s1["stime"]) / float(clk_tck)
    cpu_user_pct = round((utime_delta / elapsed) * 100.0, 2) if interval > 0 else 0.0
    cpu_sys_pct = round((stime_delta / elapsed) * 100.0, 2) if interval > 0 else 0.0
    cpu_total_pct = round(cpu_user_pct + cpu_sys_pct, 2)

    status_info = read_proc_status(pid_dir)
    sched_info = read_proc_sched(pid_dir)
    io_info, io_warn = read_proc_io(pid_dir)
    if io_warn:
        warnings.append(io_warn)
    fd_count, fd_warn = count_open_fds(pid_dir)
    if fd_warn:
        warnings.append(fd_warn)

    rss_bytes = status_info.get("VmRSS_bytes", s2["rss_pages"] * page_size)
    swap_bytes = status_info.get("VmSwap_bytes", 0)
    nonvol_switches = status_info.get("nonvoluntary_ctxt_switches", sched_info.get("nr_involuntary_switches", 0))
    vol_switches = status_info.get("voluntary_ctxt_switches", sched_info.get("nr_voluntary_switches", 0))

    status = "ok"
    if s2["state"] == "D":
        status = "warning"
        findings.append({
            "id": "PROC-STATE-001",
            "category": "process",
            "severity": "high",
            "classification": "measured",
            "title": f"Process {pid} ({s2['comm']}) is in uninterruptible sleep (D state)",
            "evidence": {
                "pid": pid,
                "comm": s2["comm"],
                "state": s2["state"],
                "iowait_sum_ms": sched_info.get("iowait_sum_ms"),
            },
            "likely_causes": ["Blocked on synchronous disk I/O, NFS mount stall, or kernel mutex contention"],
            "confidence": "high",
            "recommendation": "Inspect block device latency with scripts/inspect_io.sh and check /proc/<pid>/sched iowait_sum."
        })
        recommendations.append("Check backing storage latency for D-state process.")

    if sched_info.get("runqueue_wait_sum_ms", 0) >= 5000 or nonvol_switches > vol_switches:
        if status == "ok":
            status = "warning"
        findings.append({
            "id": "PROC-SCHED-001",
            "category": "scheduling",
            "severity": "medium",
            "classification": "measured",
            "title": f"Process {pid} ({s2['comm']}) exhibits CPU run-queue contention or involuntary preemption",
            "evidence": {
                "runqueue_wait_sum_ms": sched_info.get("runqueue_wait_sum_ms"),
                "nr_migrations": sched_info.get("nr_migrations"),
                "voluntary_ctxt_switches": vol_switches,
                "nonvoluntary_ctxt_switches": nonvol_switches,
            },
            "likely_causes": ["Thread count exceeds available CPU cores or cgroup CFS quota is throttling runnable threads"],
            "confidence": "high",
            "recommendation": "Compare process thread count against cgroup CPU quota using scripts/inspect_cgroups.py."
        })
        recommendations.append("Right-size application worker threads to reduce run-queue wait time and involuntary context switches.")

    if cpu_total_pct >= 80.0:
        status = "warning"
        findings.append({
            "id": "PROC-CPU-001",
            "category": "process",
            "severity": "medium" if cpu_total_pct < 150.0 else "high",
            "classification": "measured",
            "title": f"High process CPU utilization on PID {pid} ({cpu_total_pct}%)",
            "evidence": {"pid": pid, "comm": s2["comm"], "cpu_user_pct": cpu_user_pct, "cpu_sys_pct": cpu_sys_pct},
            "likely_causes": [
                "Tight user-space compute loop or serialization bottleneck" if cpu_user_pct >= cpu_sys_pct
                else "High syscall frequency or kernel lock contention"
            ],
            "confidence": "high",
            "recommendation": f"If opt-in active profiling is authorized, run scripts/profile_process.sh --pid {pid}"
        })

    if swap_bytes > 10 * 1024 * 1024 or s2["majflt"] > 500:
        status = "warning"
        findings.append({
            "id": "PROC-MEM-001",
            "category": "process",
            "severity": "medium",
            "classification": "measured",
            "title": f"Process {pid} experiencing swap usage or major page faults",
            "evidence": {"pid": pid, "swap_bytes": swap_bytes, "majflt": s2["majflt"], "rss_bytes": rss_bytes},
            "likely_causes": ["Working set exceeds available physical or cgroup memory"],
            "confidence": "high",
            "recommendation": "Tune process memory footprint or increase container memory.max allocation."
        })

    if not findings:
        findings.append({
            "id": "PROC-OK-001",
            "category": "process",
            "severity": "info",
            "classification": "measured",
            "title": f"Process {pid} ({s2['comm']}) telemetry within normal operating bounds",
            "evidence": {"pid": pid, "comm": s2["comm"], "state": s2["state"], "cpu_total_pct": cpu_total_pct, "rss_bytes": rss_bytes},
            "likely_causes": ["Process is healthy during observation window"],
            "confidence": "high",
            "recommendation": "Continue baseline monitoring if intermittent spikes are suspected."
        })

    return {
        "status": status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "platform": {"system": platform.system(), "release": platform.release()},
        "tool_versions": {"python": platform.python_version()},
        "findings": findings,
        "metrics": {
            "metric_semantics": {
                "cpu_pct": cpu_semantics,
                "memory_rss_and_fds": "instantaneous",
                "io_and_context_switches": "cumulative_since_process_start",
            },
            "pid": pid,
            "comm": s2["comm"],
            "state": s2["state"],
            "ppid": s2["ppid"],
            "threads": s2["num_threads"],
            "cpu": {
                "user_pct": cpu_user_pct,
                "system_pct": cpu_sys_pct,
                "total_pct": cpu_total_pct,
                "cumulative_utime_ticks": s2["utime"],
                "cumulative_stime_ticks": s2["stime"],
            },
            "memory": {
                "rss_bytes": rss_bytes,
                "vsize_bytes": s2["vsize_bytes"],
                "swap_bytes": swap_bytes,
                "minflt_cumulative": s2["minflt"],
                "majflt_cumulative": s2["majflt"],
            },
            "context_switches": {
                "voluntary_cumulative": vol_switches,
                "nonvoluntary_cumulative": nonvol_switches,
            },
            "scheduler": sched_info,
            "open_fds": fd_count,
            "io_cumulative": io_info,
        },
        "warnings": warnings,
        "recommendations": recommendations or ["No immediate process-level remediation required."],
        "errors": errors,
    }


# Keep backward-compatible alias
inspect_Single_pid = inspect_single_pid


def scan_top_processes(proc_root: Path, limit: int = 5) -> Dict[str, Any]:
    procs = []
    page_size = os.sysconf("SC_PAGE_SIZE") if hasattr(os, "sysconf") else 4096
    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        st = read_proc_stat(entry)
        if st:
            st["rss_bytes"] = st["rss_pages"] * page_size
            st["total_ticks"] = st["utime"] + st["stime"]
            procs.append(st)
    top_cpu = sorted(procs, key=lambda x: x["total_ticks"], reverse=True)[:limit]
    top_mem = sorted(procs, key=lambda x: x["rss_bytes"], reverse=True)[:limit]
    return {
        "status": "ok",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "platform": {"system": platform.system(), "release": platform.release()},
        "tool_versions": {"python": platform.python_version()},
        "findings": [{
            "id": "PROC-SCAN-001",
            "category": "process",
            "severity": "info",
            "classification": "measured",
            "title": f"Scanned {len(procs)} active processes in {proc_root}",
            "evidence": {"total_processes": len(procs), "top_rss_pid": top_mem[0]["pid"] if top_mem else None},
            "likely_causes": ["Routine process table scan"],
            "confidence": "high",
            "recommendation": "Pass --pid <PID> to inspect a specific high-resource process in detail."
        }],
        "metrics": {
            "metric_semantics": {
                "rss_bytes": "instantaneous",
                "total_ticks": "cumulative_since_process_start",
            },
            "process_count": len(procs),
            "top_by_cpu_ticks": top_cpu,
            "top_by_rss_bytes": top_mem,
        },
        "warnings": [],
        "recommendations": ["Pass --pid <PID> to inspect target process /proc/<pid>/sched and /proc/<pid>/io."],
        "errors": [],
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Collect process-level metrics from /proc.")
    parser.add_argument("--proc-root", default="/proc", help="Path to /proc directory")
    parser.add_argument("--pid", type=int, help="Specific PID to inspect (omit to list top processes)")
    parser.add_argument("--interval", type=float, default=0.1, help="Sampling window in seconds")
    parser.add_argument("--top", type=int, default=5, help="Number of top processes when --pid is omitted")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON")
    args = parser.parse_args(argv)

    proc_root = Path(args.proc_root)
    if not proc_root.exists():
        err_payload = {
            "status": "error",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "platform": {"system": platform.system(), "release": platform.release()},
            "tool_versions": {"python": platform.python_version()},
            "findings": [],
            "metrics": {},
            "warnings": [],
            "recommendations": [],
            "errors": [f"Proc root not found: {proc_root}"],
        }
        print(json.dumps(err_payload), file=sys.stderr)
        return 1

    if args.pid is not None:
        if args.pid <= 0:
            err_payload = {
                "status": "error",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "platform": {"system": platform.system(), "release": platform.release()},
                "tool_versions": {"python": platform.python_version()},
                "findings": [],
                "metrics": {},
                "warnings": [],
                "recommendations": [],
                "errors": ["PID must be a positive integer"],
            }
            print(json.dumps(err_payload), file=sys.stderr)
            return 2
        payload = inspect_single_pid(proc_root, args.pid, args.interval)
    else:
        payload = scan_top_processes(proc_root, args.top)

    print(json.dumps(payload, indent=2 if args.pretty else None))
    return 0 if payload["status"] != "error" else 1


if __name__ == "__main__":
    sys.exit(main())
