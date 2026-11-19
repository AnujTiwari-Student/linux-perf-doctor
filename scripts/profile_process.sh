#!/usr/bin/env bash
set -euo pipefail

PID=""
MODE="passive-summary"
DURATION=2
OPT_IN=0
PRETTY=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --pid)
      PID="$2"
      shift 2
      ;;
    --mode)
      MODE="$2"
      shift 2
      ;;
    --duration)
      DURATION="$2"
      shift 2
      ;;
    --enable-active-profiling)
      OPT_IN=1
      shift
      ;;
    --pretty)
      PRETTY=1
      shift
      ;;
    --help|-h)
      echo "Usage: $0 --pid <PID> [--mode passive-summary|strace-summary|perf-stat] [--duration <sec>] [--enable-active-profiling] [--pretty]"
      exit 0
      ;;
    *)
      echo '{"status":"error","timestamp":"1970-01-01T00:00:00Z","platform":{},"tool_versions":{},"findings":[],"metrics":{},"warnings":[],"recommendations":[],"errors":["Unknown argument: '"$1"'"]}' >&2
      exit 2
      ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export LPD_SCRIPT_DIR="$SCRIPT_DIR"
export LPD_PID="$PID"
export LPD_MODE="$MODE"
export LPD_DURATION="$DURATION"
export LPD_OPT_IN="$OPT_IN"
export LPD_PRETTY="$PRETTY"

python3 - <<'PY'
import json
import os
import platform
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.environ["LPD_SCRIPT_DIR"])
from common import run_bounded_command, scrub_object_secrets

pid_str = os.environ.get("LPD_PID", "")
mode = os.environ.get("LPD_MODE", "passive-summary")
duration_str = os.environ.get("LPD_DURATION", "2")
opt_in = os.environ.get("LPD_OPT_IN") == "1"
pretty = os.environ.get("LPD_PRETTY") == "1"

def emit_error(msg: str, code: int):
    payload = {
        "status": "error",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "platform": {"system": platform.system(), "release": platform.release()},
        "tool_versions": {"python": platform.python_version()},
        "findings": [],
        "metrics": {},
        "warnings": [],
        "recommendations": [],
        "errors": [msg],
    }
    print(json.dumps(payload), file=sys.stderr)
    sys.exit(code)

if not pid_str:
    emit_error("Missing required --pid argument", 2)

try:
    pid = int(pid_str)
    duration = max(1, min(int(duration_str), 30))
except ValueError:
    emit_error("Invalid PID or duration", 2)

if not Path(f"/proc/{pid}").exists():
    emit_error(f"Process {pid} does not exist", 1)

if mode in ("strace-summary", "perf-stat") and not opt_in:
    emit_error(f"Active profiling mode '{mode}' requires explicit --enable-active-profiling flag for safety.", 2)

warnings = []
findings = []
metrics = {"pid": pid, "mode": mode, "duration_seconds": duration}

if mode == "passive-summary":
    syscall_content = None
    wchan_content = None
    try:
        syscall_content = Path(f"/proc/{pid}/syscall").read_text(encoding="utf-8", errors="replace").strip()[:256]
    except Exception as exc:
        warnings.append(f"Cannot read /proc/{pid}/syscall: {exc}")
    try:
        wchan_content = Path(f"/proc/{pid}/wchan").read_text(encoding="utf-8", errors="replace").strip()[:256]
    except Exception as exc:
        warnings.append(f"Cannot read /proc/{pid}/wchan: {exc}")
    metrics["current_syscall"] = syscall_content
    metrics["wchan"] = wchan_content
    findings.append({
        "id": "PROF-PASSIVE-001",
        "category": "profiling",
        "severity": "info",
        "classification": "measured",
        "title": f"Captured passive kernel wait-channel and syscall snapshot for PID {pid}",
        "evidence": {"wchan": wchan_content, "syscall": syscall_content},
        "likely_causes": ["Read-only inspection of kernel thread state"],
        "confidence": "high",
        "recommendation": "Pass --mode strace-summary --enable-active-profiling only if syscall histogram is needed."
    })
elif mode == "strace-summary":
    if not shutil.which("strace"):
        warnings.append("strace binary is not installed; falling back to passive /proc/<pid>/syscall inspection.")
        findings.append({
            "id": "PROF-STRACE-FALLBACK",
            "category": "profiling",
            "severity": "info",
            "classification": "measured",
            "title": "strace not installed on host; active trace skipped safely",
            "evidence": {"strace_available": False},
            "likely_causes": ["Minimal container or host environment without strace package"],
            "confidence": "high",
            "recommendation": "Install strace or rely on collect_process_metrics.py context-switch and system-CPU ratios."
        })
    else:
        res = run_bounded_command(["timeout", str(duration), "strace", "-c", "-p", str(pid)], timeout_sec=duration + 3.0, max_bytes=16384)
        metrics["strace_output"] = (res["stderr"] or res["stdout"] or "")[-4000:]
        metrics["output_truncated"] = res["truncated"]
        findings.append({
            "id": "PROF-STRACE-001",
            "category": "profiling",
            "severity": "info",
            "classification": "measured",
            "title": f"Executed {duration}s strace syscall summary on PID {pid}",
            "evidence": {"return_code": res["returncode"], "truncated": res["truncated"]},
            "likely_causes": ["Active opt-in syscall profiling"],
            "confidence": "high",
            "recommendation": "Review top syscalls by time and error count in metrics.strace_output."
        })
elif mode == "perf-stat":
    if not shutil.which("perf"):
        warnings.append("perf binary is not installed; falling back to passive telemetry.")
        findings.append({
            "id": "PROF-PERF-FALLBACK",
            "category": "profiling",
            "severity": "info",
            "classification": "measured",
            "title": "perf not installed on host; hardware counter profiling skipped safely",
            "evidence": {"perf_available": False},
            "likely_causes": ["linux-tools/perf package not installed"],
            "confidence": "high",
            "recommendation": "Use scripts/collect_process_metrics.py for software CPU tick and page fault accounting."
        })
    else:
        res = run_bounded_command(["perf", "stat", "-p", str(pid), "sleep", str(duration)], timeout_sec=duration + 3.0, max_bytes=16384)
        metrics["perf_output"] = (res["stderr"] or res["stdout"] or "")[-4000:]
        metrics["output_truncated"] = res["truncated"]
        findings.append({
            "id": "PROF-PERF-001",
            "category": "profiling",
            "severity": "info",
            "classification": "measured",
            "title": f"Executed {duration}s perf stat sample on PID {pid}",
            "evidence": {"return_code": res["returncode"], "truncated": res["truncated"]},
            "likely_causes": ["Active opt-in hardware PMU profiling"],
            "confidence": "high",
            "recommendation": "Inspect IPC and cache-miss counters in metrics.perf_output."
        })
else:
    emit_error(f"Unsupported mode: {mode}", 2)

payload = {
    "status": "ok",
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "platform": {"system": platform.system(), "release": platform.release()},
    "tool_versions": {"python": platform.python_version()},
    "findings": findings,
    "metrics": metrics,
    "warnings": warnings,
    "recommendations": ["Use passive telemetry for continuous monitoring."],
    "errors": [],
}
print(json.dumps(scrub_object_secrets(payload), indent=2 if pretty else None))
PY
