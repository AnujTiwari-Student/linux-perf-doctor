# Model Context Protocol (MCP) Server Conversion Roadmap (`linux-perf-doctor`)

> **Scope Note**: This document defines the engineering blueprint for exposing `linux-perf-doctor` as a standalone Model Context Protocol (MCP) server (`linux-perf-doctor-mcp`). The current repository operates as a zero-dependency Agent Skill (`SKILL.md` + CLI scripts) with no external MCP SDK runtime requirement.

## 1. Proposed MCP Server Architecture
The MCP server wraps the existing deterministic Python core modules (`scripts/common.py`, `scripts/collect_system_metrics.py`, `scripts/collect_process_metrics.py`, `scripts/inspect_cgroups.py`, `scripts/inspect_network.py`, `scripts/generate_report.py`) behind a thin JSON-RPC 2.0 adapter layer:
- **Core Domain Layer (Already Implemented)**: Pure Python standard-library analyzers, parsers, credential scrubbers, and `validate_against_schema()` validators in `scripts/`.
- **MCP Adapter Layer (Future `mcp_server/server.py`)**: Maps MCP `tools/list`, `tools/call`, `resources/list`, `resources/read`, and `prompts/get` requests directly to the pure Python functions in `scripts/`, avoiding subprocess spawning overhead for in-process Python modules while retaining `run_bounded_command()` for external OS utilities.

## 2. Reusable Core Functionality
All business logic in `scripts/common.py`, `scripts/collect_system_metrics.py`, `scripts/collect_process_metrics.py`, `scripts/inspect_cgroups.py`, `scripts/inspect_network.py`, `scripts/generate_report.py` is already structured as importable, side-effect-free Python functions returning deterministic dictionaries validated against `schemas/*.schema.json`. Zero core analysis logic needs to be rewritten for MCP conversion.

## 3. Proposed MCP Tools, Input Schemas & Output Schemas

| Tool Name | Purpose | Input JSON Schema | Output JSON Schema |
| :--- | :--- | :--- | :--- |
| `check_perf_capabilities` | Inspect kernel security guards (perf_event_paranoid, ptrace_scope) and CapEff bitmask. | `{"type":"object","properties":{"proc_root":{"type":"string","default":"/proc"}}}` | `schemas/*.schema.json` |
| `collect_system_metrics` | Sample passive host CPU, memory, PSI, and vmstat counters. | `{"type":"object","properties":{"proc_root":{"type":"string","default":"/proc"},"interval":{"type":"number","default":0.2,"maximum":10.0},"samples":{"type":"integer","default":2,"maximum":5}}}` | `schemas/*.schema.json` |
| `inspect_process_metrics` | Collect /proc/<pid>/stat, status, sched, fd, and io telemetry for a target PID. | `{"type":"object","required":["pid"],"properties":{"pid":{"type":"integer","minimum":1},"interval":{"type":"number","default":0.2,"maximum":10.0}}}` | `schemas/*.schema.json` |
| `inspect_cgroups` | Analyze cgroup v1/v2 CPU throttling, memory events, and per-cgroup PSI stalls. | `{"type":"object","properties":{"cgroup_root":{"type":"string","default":"/sys/fs/cgroup"}}}` | `schemas/*.schema.json` |
| `inspect_network_and_io` | Parse /proc/net/{tcp,snmp,netstat,dev} and /proc/diskstats interval deltas. | `{"type":"object","properties":{"proc_root":{"type":"string","default":"/proc"},"io_interval":{"type":"number","default":0.1}}}` | `schemas/*.schema.json` |
| `generate_perf_report` | Synthesize all passive collectors into a correlated bottleneck diagnosis. | `{"type":"object","properties":{"pid":{"type":"integer"},"interval":{"type":"number","default":0.1}}}` | `schemas/*.schema.json` |

## 4. Proposed MCP Resources
- **`perf://host/capabilities`**: Cached host kernel capability and profiler inventory JSON
- **`perf://references/technical-reference`**: Kernel counter and PSI threshold reference markdown

## 5. Reusable Workflow Prompts
- **`diagnose-container-latency`**: Guided workflow comparing cgroup CFS throttling against host CPU idle %
- **`investigate-oom-or-leak`**: Guided workflow correlating vmstat/cgroup oom_kill with top RSS processes

## 6. Permission Boundaries & Security Requirements
- **Read-Only Default Execution**: All diagnostic tools execute in read-only mode. Any opt-in active profiler or file-scaffolding tool requires explicit boolean confirmation parameters (`enable_active_profiling=true` or `dry_run=false`) and path-traversal validation (`resolve_safe_child_path`).
- **Mandatory Output Sanitization**: Every MCP tool response passes through the centralized credential redaction pipeline (`redact_credentials` / `scrub_text_secrets`) before serialization over JSON-RPC.
- **True Streaming Subprocess Limits**: All external binary invocations enforce `run_bounded_command()` with streaming byte caps (`64 KiB` default), `shell=False`, process-group termination on limit/timeout violation, a strict executable allowlist, and refusal of mutating subcommands.

## 7. Transport Plan: `stdio` and Streamable HTTP
1. **`stdio` Transport (Local IDE & CLI Agents)**:
   - Entrypoint: `python3 -m mcp_server --transport stdio`
   - Communicates over newline-delimited JSON-RPC 2.0 on `stdin`/`stdout`, logging diagnostic errors exclusively to `stderr`.
2. **Streamable HTTP Transport (Remote / Containerized Agent Gateways)**:
   - Entrypoint: `python3 -m mcp_server --transport streamable-http --host 127.0.0.1 --port 8765`
   - Implements the MCP `/mcp` single-endpoint POST/GET SSE streamable HTTP specification with request body size limits (`<= 1 MiB`) and per-request execution timeouts.

## 8. Authentication and Access-Control Requirements
- **`stdio` Mode**: Inherits local OS user UID/GID and Linux capability bounding set; never escalates privileges.
- **Streamable HTTP Mode**: Binds to `127.0.0.1` by default. When exposed across a network, requires `Authorization: Bearer <token>` validated via constant-time comparison (`hmac.compare_digest`), mTLS client certificate verification, and origin header validation to prevent DNS rebinding.

## 9. Testing Strategy
- **Contract Tests**: Validate every MCP tool's input and output payload against `schemas/*.schema.json`.
- **Transport Tests**: Verify JSON-RPC 2.0 framing, error codes (`-32602` Invalid Params, `-32603` Internal Error), timeout cancellation, and secret redaction over both `stdio` pipes and HTTP loopback requests.

## 10. Future Implementation Milestones
- **Phase 1 (Completed)**: Deterministic Python core modules, streaming bounded subprocess runner, credential redaction, and formal JSON Schemas.
- **Phase 2**: Add lightweight zero-dependency JSON-RPC 2.0 `stdio` dispatcher (`scripts/mcp_stdio_bridge.py`).
- **Phase 3**: Add Streamable HTTP transport with Bearer token authentication and rate limiting.
