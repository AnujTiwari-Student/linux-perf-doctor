#!/usr/bin/env bash
set -euo pipefail

PROC_ROOT="/proc"
INTERVAL="0"
PRETTY=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --proc-root)
      PROC_ROOT="$2"
      shift 2
      ;;
    --interval)
      INTERVAL="$2"
      shift 2
      ;;
    --pretty)
      PRETTY=1
      shift
      ;;
    --help|-h)
      echo "Usage: $0 [--proc-root /proc] [--interval <sec>] [--pretty]"
      exit 0
      ;;
    *)
      echo '{"status":"error","timestamp":"1970-01-01T00:00:00Z","platform":{},"tool_versions":{},"findings":[],"metrics":{},"warnings":[],"recommendations":[],"errors":["Unknown argument: '"$1"'"]}' >&2
      exit 2
      ;;
  esac
done

python3 - "$PROC_ROOT" "$INTERVAL" "$PRETTY" <<'PY'
import json
import os
import platform
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

proc_root = Path(sys.argv[1] if len(sys.argv) > 1 and sys.argv[1] else "/proc")
pretty = (sys.argv[3] == "1") if len(sys.argv) > 3 else False
try:
    interval = float(sys.argv[2] if len(sys.argv) > 2 and sys.argv[2] else "0")
except ValueError:
    interval = -1.0

if interval < 0 or interval > 60:
    print(json.dumps({
        "status": "error",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "platform": {},
        "tool_versions": {},
        "findings": [],
        "metrics": {},
        "warnings": [],
        "recommendations": [],
        "errors": ["Interval must be between 0 and 60 seconds"]
    }), file=sys.stderr)
    sys.exit(2)

if not proc_root.exists():
    print(json.dumps({
        "status": "error",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "platform": {},
        "tool_versions": {},
        "findings": [],
        "metrics": {},
        "warnings": [],
        "recommendations": [],
        "errors": [f"Proc root not found: {proc_root}"]
    }), file=sys.stderr)
    sys.exit(1)

def read_diskstats(p: Path):
    out = {}
    if not p.exists():
        return out
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.strip().split()
        if len(parts) < 14:
            continue
        dev = parts[2]
        if dev.startswith("loop"):
            continue
        out[dev] = {
            "reads_completed": int(parts[3]),
            "sectors_read": int(parts[5]),
            "read_time_ms": int(parts[6]),
            "writes_completed": int(parts[7]),
            "sectors_written": int(parts[9]),
            "write_time_ms": int(parts[10]),
            "io_in_progress": int(parts[11]),
            "io_time_ms": int(parts[12]),
            "weighted_io_time_ms": int(parts[13]),
        }
    return out

diskstats_path = proc_root / "diskstats"
devices = []
warnings = []
errors = []
findings = []
recommendations = []

if diskstats_path.exists():
    s1 = read_diskstats(diskstats_path)
    if interval > 0:
        t0 = time.monotonic()
        time.sleep(min(interval, 10.0))
        elapsed = max(time.monotonic() - t0, 0.001)
        s2 = read_diskstats(diskstats_path)
        mode = "interval_delta"
    else:
        elapsed = 0.0
        s2 = s1
        mode = "cumulative_since_boot"

    for dev_name, d2 in s2.items():
        d1 = s1.get(dev_name, d2)
        r_comp = d2["reads_completed"]
        w_comp = d2["writes_completed"]
        r_ms = d2["read_time_ms"]
        w_ms = d2["write_time_ms"]

        cum_r_await = round(r_ms / r_comp, 2) if r_comp > 0 else 0.0
        cum_w_await = round(w_ms / w_comp, 2) if w_comp > 0 else 0.0

        dev_entry = {
            "device": dev_name,
            "instantaneous_io_in_progress": d2["io_in_progress"],
            "cumulative": {
                "reads_completed": r_comp,
                "bytes_read": d2["sectors_read"] * 512,
                "read_time_ms": r_ms,
                "avg_read_await_ms": cum_r_await,
                "writes_completed": w_comp,
                "bytes_written": d2["sectors_written"] * 512,
                "write_time_ms": w_ms,
                "avg_write_await_ms": cum_w_await,
                "io_time_ms": d2["io_time_ms"],
                "weighted_io_time_ms": d2["weighted_io_time_ms"],
            },
            # Keep top-level compatibility fields while adding interval_delta
            "reads_completed": r_comp,
            "bytes_read": d2["sectors_read"] * 512,
            "avg_read_await_ms": cum_r_await,
            "writes_completed": w_comp,
            "bytes_written": d2["sectors_written"] * 512,
            "avg_write_await_ms": cum_w_await,
            "io_in_progress": d2["io_in_progress"],
        }

        if interval > 0:
            dr = max(0, d2["reads_completed"] - d1["reads_completed"])
            dw = max(0, d2["writes_completed"] - d1["writes_completed"])
            dr_sec = max(0, d2["sectors_read"] - d1["sectors_read"])
            dw_sec = max(0, d2["sectors_written"] - d1["sectors_written"])
            dr_ms = max(0, d2["read_time_ms"] - d1["read_time_ms"])
            dw_ms = max(0, d2["write_time_ms"] - d1["write_time_ms"])
            dio_ms = max(0, d2["io_time_ms"] - d1["io_time_ms"])
            dev_entry["interval_delta"] = {
                "window_seconds": round(elapsed, 3),
                "read_iops": round(dr / elapsed, 2),
                "write_iops": round(dw / elapsed, 2),
                "read_bytes_per_sec": round((dr_sec * 512) / elapsed, 2),
                "write_bytes_per_sec": round((dw_sec * 512) / elapsed, 2),
                "interval_read_await_ms": round(dr_ms / dr, 2) if dr > 0 else 0.0,
                "interval_write_await_ms": round(dw_ms / dw, 2) if dw > 0 else 0.0,
                "utilization_pct": round(min(100.0, (dio_ms / (elapsed * 1000.0)) * 100.0), 2),
            }
        devices.append(dev_entry)
else:
    mode = "unavailable"
    warnings.append(f"{diskstats_path} not present; block device counters unavailable in this container/environment.")

status = "ok"
slow_devs = [
    d for d in devices
    if d["avg_read_await_ms"] >= 25.0
    or d["avg_write_await_ms"] >= 25.0
    or d["io_in_progress"] >= 16
    or (d.get("interval_delta", {}).get("interval_write_await_ms", 0.0) >= 25.0)
]
if slow_devs:
    status = "warning"
    findings.append({
        "id": "IO-DISK-001",
        "category": "io",
        "severity": "medium",
        "classification": "measured",
        "title": f"Elevated block device latency or queue depth on {len(slow_devs)} device(s)",
        "evidence": {"slow_devices": slow_devs, "measurement_mode": mode},
        "likely_causes": [
            "Backing volume IOPS/throughput throttling (e.g., cloud block storage burst credit depletion)",
            "Heavy synchronous write workload or unindexed database full-table scans"
        ],
        "confidence": "high",
        "recommendation": "Correlate high-await devices with per-process /proc/<pid>/io write_bytes and check database/application fsync frequency."
    })
    recommendations.append("Reduce synchronous disk flushes or provision higher IOPS storage for saturated block devices.")
else:
    findings.append({
        "id": "IO-OK-001",
        "category": "io",
        "severity": "info",
        "classification": "measured",
        "title": "Block device latency and queue depths within normal thresholds",
        "evidence": {"devices_inspected": len(devices), "measurement_mode": mode},
        "likely_causes": ["Storage subsystem operating normally"],
        "confidence": "high",
        "recommendation": "No block I/O bottlenecks detected."
    })

payload = {
    "status": status,
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "platform": {"system": platform.system(), "release": platform.release()},
    "tool_versions": {"python": platform.python_version(), "iostat_available": shutil.which("iostat") is not None},
    "findings": findings,
    "metrics": {
        "metric_semantics": {
            "io_in_progress": "instantaneous",
            "cumulative": "cumulative_since_boot",
            "interval_delta": "interval_derived" if interval > 0 else "not_sampled",
        },
        "block_devices": devices,
    },
    "warnings": warnings,
    "recommendations": recommendations or ["No block I/O remediation required."],
    "errors": errors,
}
print(json.dumps(payload, indent=2 if pretty else None))
PY
