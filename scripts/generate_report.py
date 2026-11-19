#!/usr/bin/env python3
"""Synthesize system, process, cgroup, I/O, and network telemetry into a unified diagnostic report."""
import argparse
import json
import os
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import collect_process_metrics
import collect_system_metrics
import inspect_cgroups
import inspect_network
from common import run_bounded_command, scrub_object_secrets, scrub_text_secrets


def run_io_collector(proc_root: Path, interval: float = 0.0) -> Dict[str, Any]:
    io_script = SCRIPT_DIR / "inspect_io.sh"
    res = run_bounded_command(
        [str(io_script), "--proc-root", str(proc_root), "--interval", str(interval)],
        timeout_sec=max(5.0, interval + 5.0),
        max_bytes=65536,
    )
    if res["ok"] and res["stdout"].strip():
        try:
            return json.loads(res["stdout"])
        except Exception as exc:
            return {"status": "error", "findings": [], "metrics": {}, "warnings": [str(exc)], "recommendations": [], "errors": [str(exc)]}
    return {"status": "error", "findings": [], "metrics": {}, "warnings": [], "recommendations": [], "errors": [res["stderr"] or "Failed to run inspect_io.sh"]}


def build_unified_report(proc_root: Path, cgroup_root: Path, pid: Optional[int], interval: float) -> Dict[str, Any]:
    sys_rep = collect_system_metrics.collect_system_metrics(proc_root, interval=interval, samples=2 if interval > 0 else 1)
    cgrp_rep = inspect_cgroups.inspect_cgroups(cgroup_root)
    net_rep = inspect_network.inspect_network(proc_root)
    io_rep = run_io_collector(proc_root, interval=0.0)
    if pid is not None:
        proc_rep = collect_process_metrics.inspect_single_pid(proc_root, pid, interval=interval)
    else:
        proc_rep = collect_process_metrics.scan_top_processes(proc_root, limit=5)

    subsystems = {
        "system": sys_rep,
        "cgroup": cgrp_rep,
        "io": io_rep,
        "network": net_rep,
        "process": proc_rep,
    }

    all_findings: List[Dict[str, Any]] = []
    all_warnings: List[str] = []
    all_recommendations: List[str] = []
    all_errors: List[str] = []

    severity_rank = {"critical": 3, "warning": 2, "ok": 1, "error": 0}
    overall_status = "ok"

    for _, rep in subsystems.items():
        st = rep.get("status", "ok")
        if severity_rank.get(st, 1) > severity_rank.get(overall_status, 1):
            overall_status = st
        all_findings.extend(rep.get("findings", []))
        all_warnings.extend(rep.get("warnings", []))
        all_recommendations.extend(rep.get("recommendations", []))
        all_errors.extend(rep.get("errors", []))

    # Cross-subsystem correlation hypothesis
    hypotheses: List[Dict[str, Any]] = []
    cgrp_throttled = any(f.get("id") == "CGRP-CPU-001" for f in all_findings)
    if cgrp_throttled:
        hypotheses.append({
            "id": "HYP-CGRP-QUOTA",
            "category": "correlation",
            "severity": "high",
            "classification": "hypothesis",
            "title": "Container CFS quota throttling is actively restricting application threads",
            "evidence": {
                "cgroup_throttle_pct": cgrp_rep.get("metrics", {}).get("cpu", {}).get("throttle_pct"),
                "host_idle_pct": sys_rep.get("metrics", {}).get("cpu", {}).get("idle_pct"),
            },
            "likely_causes": ["Container CPU quota (cpu.max / cfs_quota_us) is exhausted within 100ms scheduling periods"],
            "confidence": "high",
            "recommendation": "Raise container CPU limit or right-size worker thread pool count to match container effective CPUs."
        })

    all_findings.extend(hypotheses)
    bottlenecks = [f for f in all_findings if f.get("severity") in ("critical", "high", "medium")]

    return scrub_object_secrets({
        "status": overall_status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "platform": sys_rep.get("platform", {}),
        "tool_versions": {"python": platform.python_version()},
        "findings": all_findings,
        "bottlenecks": bottlenecks,
        "metrics": {
            "system": sys_rep.get("metrics", {}),
            "cgroup": cgrp_rep.get("metrics", {}),
            "io": io_rep.get("metrics", {}),
            "network": net_rep.get("metrics", {}),
            "process": proc_rep.get("metrics", {}),
        },
        "warnings": list(dict.fromkeys(all_warnings)),
        "recommendations": list(dict.fromkeys(all_recommendations)) or [
            "Maintain baseline telemetry collection and alert on cgroup nr_throttled or PSI stall spikes."
        ],
        "errors": all_errors,
    })


def render_markdown(report: Dict[str, Any]) -> str:
    sys_m = report["metrics"].get("system", {})
    cpu_m = sys_m.get("cpu", {})
    mem_m = sys_m.get("memory", {})
    cgrp_m = report["metrics"].get("cgroup", {})
    net_m = report["metrics"].get("network", {})
    proc_m = report["metrics"].get("process", {})

    lines = [
        "# Linux Performance Diagnostic Report (`linux-perf-doctor`)",
        "",
        f"- **Overall Health Status**: `{report['status'].upper()}`",
        f"- **Timestamp (UTC)**: `{report['timestamp']}`",
        f"- **Kernel / Arch**: `{report['platform'].get('release', 'unknown')}` (`{report['platform'].get('machine', 'unknown')}`)",
        "",
        "## 1. Detected Bottlenecks & Hypotheses",
        "",
    ]
    bottlenecks = [f for f in report["findings"] if f.get("severity") in ("critical", "high", "medium") or f.get("classification") == "hypothesis"]
    if not bottlenecks:
        lines.append("- No active critical/high/medium bottlenecks detected during the sampling window.")
    else:
        for b in bottlenecks:
            lines.extend([
                f"### [{b['severity'].upper()}] {b['id']}: {b['title']}",
                f"- **Classification**: `{b['classification']}` (Confidence: `{b['confidence']}`)",
                f"- **Evidence**: `{json.dumps(b['evidence'])}`",
                f"- **Likely Causes**: {'; '.join(b.get('likely_causes', []))}",
                f"- **Recommended Action**: {b.get('recommendation', '')}",
                "",
            ])

    lines.extend([
        "## 2. Subsystem Telemetry Summary",
        "",
        "### CPU & Scheduling",
        f"- **User / System / Idle / IOWait**: `{cpu_m.get('user_pct', 0)}%` / `{cpu_m.get('system_pct', 0)}%` / `{cpu_m.get('idle_pct', 0)}%` / `{cpu_m.get('iowait_pct', 0)}%` (`{cpu_m.get('semantics', 'interval_derived')}`)",
        f"- **Context Switches / sec**: `{cpu_m.get('ctxt_per_sec', 0)}`",
        f"- **Run Queue (Running / Blocked)**: `{sys_m.get('scheduling', {}).get('procs_running', 0)}` / `{sys_m.get('scheduling', {}).get('procs_blocked', 0)}`",
        "",
        "### Memory",
        f"- **Host Memory Used**: `{mem_m.get('mem_used_pct', 0)}%` (`{mem_m.get('mem_used_bytes', 0)}` / `{mem_m.get('mem_total_bytes', 0)}` bytes)",
        f"- **Swap Used**: `{mem_m.get('swap_used_pct', 0)}%`",
        "",
        "### Container / Cgroup (`" + str(cgrp_m.get("cgroup_version", "unknown")) + "`)",
        f"- **CPU Quota / Throttle %**: `{cgrp_m.get('cpu', {}).get('effective_cpus', 'unlimited')}` CPUs / `{cgrp_m.get('cpu', {}).get('throttle_pct', 0)}%` throttled",
        f"- **Cgroup Memory Utilization**: `{cgrp_m.get('memory', {}).get('utilization_pct', 'N/A')}%`",
        f"- **Per-Cgroup PSI**: `{json.dumps(cgrp_m.get('pressure', {}))}`",
        "",
        "### Network",
        f"- **TCP States**: `{json.dumps(net_m.get('tcp_state_counts', {}))}`",
        f"- **TCP Retransmission %**: `{net_m.get('tcp_retransmission_pct', 0.0)}%`",
        f"- **Queued Sockets**: `{len(net_m.get('queued_sockets', []))}`",
        "",
        "### Process Analysis",
        f"- **Process Summary**: `{json.dumps(proc_m)[:400]}`",
        "",
        "## 3. Recommended Next Diagnostic Actions",
        "",
    ])
    for rec in report.get("recommendations", []):
        lines.append(f"- {rec}")
    return scrub_text_secrets("\n".join(lines) + "\n")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Generate unified Linux performance report.")
    parser.add_argument("--proc-root", default="/proc", help="Path to /proc root")
    parser.add_argument("--cgroup-root", default="/sys/fs/cgroup", help="Path to cgroup root")
    parser.add_argument("--pid", type=int, help="Optional target PID")
    parser.add_argument("--interval", type=float, default=0.1, help="Sampling interval in seconds")
    parser.add_argument("--format", choices=["json", "markdown"], default="json", help="Output format")
    parser.add_argument("--output", help="Optional output file path")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")
    args = parser.parse_args(argv)

    report = build_unified_report(Path(args.proc_root), Path(args.cgroup_root), args.pid, args.interval)
    if args.format == "markdown":
        rendered = render_markdown(report)
    else:
        rendered = json.dumps(report, indent=2 if args.pretty else None)

    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    sys.exit(main())
