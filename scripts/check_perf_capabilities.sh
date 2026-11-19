#!/usr/bin/env bash
set -euo pipefail

PROC_ROOT="/proc"
PRETTY=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --proc-root)
      PROC_ROOT="$2"
      shift 2
      ;;
    --pretty)
      PRETTY=1
      shift
      ;;
    --help|-h)
      echo "Usage: $0 [--proc-root /proc] [--pretty]"
      exit 0
      ;;
    *)
      echo '{"status":"error","timestamp":"1970-01-01T00:00:00Z","platform":{},"tool_versions":{},"findings":[],"metrics":{},"warnings":[],"recommendations":[],"errors":["Unknown argument: '"$1"'"]}' >&2
      exit 2
      ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export LPD_PROC_ROOT="$PROC_ROOT"
export LPD_PRETTY="$PRETTY"
export LPD_SCRIPT_DIR="$SCRIPT_DIR"

python3 - <<'PY'
import json
import os
import platform
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.environ["LPD_SCRIPT_DIR"])
from common import decode_cap_eff_hex, run_bounded_command

proc_root = Path(os.environ.get("LPD_PROC_ROOT", "/proc"))
pretty = os.environ.get("LPD_PRETTY") == "1"

tools = [
    "perf", "strace", "ss", "iostat", "vmstat", "pidstat",
    "top", "dmesg", "bpftool", "bpftrace", "execsnoop-bpfcc", "biolatency-bpfcc", "ip"
]
tool_info = {}
tool_versions = {"python": platform.python_version()}

for t in tools:
    path = shutil.which(t)
    available = path is not None
    version_str = None
    if available:
        for flag in ["--version", "-V", "-v"]:
            res = run_bounded_command([t, flag], timeout_sec=2.0, max_bytes=4096)
            out = (res["stdout"] or res["stderr"] or "").strip().splitlines()
            if out and res["returncode"] in (0, 1):
                version_str = out[0][:120]
                break
    tool_info[t] = {"available": available, "path": path}
    if version_str:
        tool_versions[t] = version_str

def read_first_line(path: Path):
    try:
        if path.exists():
            return path.read_text(encoding="utf-8", errors="replace").splitlines()[0].strip()
    except Exception:
        pass
    return None

def read_cap_eff(proc_path: Path):
    status_file = proc_path / "self" / "status"
    if not status_file.exists():
        status_file = proc_path / "1" / "status"
    if status_file.exists():
        try:
            for line in status_file.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.startswith("CapEff:"):
                    return line.split(":", 1)[1].strip()
        except Exception:
            pass
    return "0000000000000000"

paranoid = read_first_line(proc_root / "sys/kernel/perf_event_paranoid")
ptrace_scope = read_first_line(proc_root / "sys/kernel/yama/ptrace_scope")
kptr_restrict = read_first_line(proc_root / "sys/kernel/kptr_restrict")
dmesg_restrict = read_first_line(proc_root / "sys/kernel/dmesg_restrict")

cap_eff_raw = read_cap_eff(proc_root)
cap_decoded = decode_cap_eff_hex(cap_eff_raw)
caps = cap_decoded.get("capabilities", {})

cgroup_v2 = os.path.exists("/sys/fs/cgroup/cgroup.controllers")
cgroup_v1 = os.path.exists("/sys/fs/cgroup/memory") or os.path.exists("/sys/fs/cgroup/cpu")
psi_available = (proc_root / "pressure/cpu").exists()

warnings = []
recommendations = []
findings = []

if not caps.get("CAP_PERFMON", False) and not caps.get("CAP_SYS_ADMIN", False):
    if paranoid is not None and paranoid.lstrip("-").isdigit() and int(paranoid) >= 2:
        warnings.append(f"Unprivileged process lacks CAP_PERFMON/CAP_SYS_ADMIN and kernel.perf_event_paranoid={paranoid}.")
        recommendations.append("Use passive /proc and cgroup telemetry collectors, or grant CAP_PERFMON for hardware PMU profiling.")

if not caps.get("CAP_SYS_PTRACE", False):
    if ptrace_scope is not None and ptrace_scope.isdigit() and int(ptrace_scope) >= 1:
        warnings.append(f"Process lacks CAP_SYS_PTRACE and kernel.yama.ptrace_scope={ptrace_scope} restricts attaching strace to non-child PIDs.")
        recommendations.append("Rely on /proc/[pid]/sched and /proc/[pid]/status context-switch counters when CAP_SYS_PTRACE is unavailable.")

if not caps.get("CAP_BPF", False) and not caps.get("CAP_SYS_ADMIN", False):
    warnings.append("Process lacks CAP_BPF and CAP_SYS_ADMIN; eBPF program loading (bpftool/bpftrace/bcc) is restricted.")

missing_tools = [k for k, v in tool_info.items() if not v["available"]]
if missing_tools:
    warnings.append("Unavailable optional CLI utilities: " + ", ".join(missing_tools))

findings.append({
    "id": "CAP-001",
    "category": "capabilities",
    "severity": "info",
    "classification": "measured",
    "title": "Completed Linux capability bitmask (CapEff), sysctl security guard, and profiler binary inventory",
    "evidence": {
        "cap_eff_hex": cap_eff_raw,
        "CAP_PERFMON": caps.get("CAP_PERFMON", False),
        "CAP_SYS_PTRACE": caps.get("CAP_SYS_PTRACE", False),
        "CAP_BPF": caps.get("CAP_BPF", False),
        "CAP_SYS_ADMIN": caps.get("CAP_SYS_ADMIN", False),
        "perf_event_paranoid": paranoid,
        "ptrace_scope": ptrace_scope,
        "kptr_restrict": kptr_restrict,
        "cgroup_v2": cgroup_v2,
        "cgroup_v1": cgroup_v1,
        "psi_available": psi_available,
    },
    "likely_causes": ["Host kernel security posture and container capability bounding set"],
    "confidence": "high",
    "recommendation": "Use passive /proc and /sys collectors by default; invoke active profilers only when permitted and explicitly opted in."
})

payload = {
    "status": "ok",
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "platform": {
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python_version": platform.python_version(),
        "euid": os.geteuid() if hasattr(os, "geteuid") else None,
    },
    "tool_versions": tool_versions,
    "findings": findings,
    "metrics": {
        "metric_semantics": "instantaneous",
        "capabilities": cap_decoded,
        "tools": tool_info,
        "kernel_guards": {
            "perf_event_paranoid": paranoid,
            "ptrace_scope": ptrace_scope,
            "kptr_restrict": kptr_restrict,
            "dmesg_restrict": dmesg_restrict,
        },
        "filesystems": {
            "proc_mounted": (proc_root / "stat").exists(),
            "sys_mounted": os.path.exists("/sys/fs"),
            "cgroup_v2": cgroup_v2,
            "cgroup_v1": cgroup_v1,
            "psi_available": psi_available,
        },
    },
    "warnings": warnings,
    "recommendations": recommendations or ["Capability baseline verified."],
    "errors": [],
}

print(json.dumps(payload, indent=2 if pretty else None))
PY
