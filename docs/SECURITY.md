# Security & Safety Model

This document describes the security boundaries, execution behavior, data
collection practices, and limitations of linux-perf-doctor.

The guarantees below describe the current implementation. Secret redaction
and read-only diagnostics reduce risk but do not guarantee that all sensitive
information will be detected or removed.

## 1. Core Security Guarantees

### 1.1 Read-only Default Diagnostics

Default diagnostic collection reads Linux kernel interfaces, including:

- `/proc`
- `/sys`
- `/sys/fs/cgroup`
- `/proc/pressure`
- `/proc/diskstats`
- `/proc/net`

Passive collection does not intentionally modify kernel parameters, process
scheduling priorities, process state, or system configuration.

The report generator may create a diagnostic report at the output location
specified by the user. This is separate from modifying host operating-system
state.

### 1.2 No Automatic Privilege Escalation

The scripts do not automatically invoke privilege-escalation wrappers.

The shared subprocess execution helper also rejects these privilege-escalation
executables.

Diagnostics run with the privileges of the invoking user. When access to a
process or kernel interface is restricted, the relevant collector should
record an error or warning and continue where possible.

Users must not interpret missing telemetry as proof that a subsystem is
healthy. Permission restrictions can prevent complete inspection.

### 1.3 Explicit Consent for Active Profiling

Passive inspection is the default.

The following active profiling modes require explicit opt-in:

- `strace-summary`
- `perf-stat`

Users must explicitly provide `--enable-active-profiling` before these modes
can execute.

Active profiling attaches external tools to the selected target process.
It can introduce performance overhead and affect timing-sensitive workloads.
Use it only when authorized and appropriate for the target environment.

Active profiling duration is clamped to 1–30 seconds. The profiler
command is executed through the `timeout` utility, while the shared
subprocess helper applies an outer timeout of the requested duration plus
three seconds.

### 1.4 Target Process Data Boundaries

The reviewed collectors inspect selected process and kernel telemetry,
including process CPU counters, memory information, file descriptor counts,
I/O counters, syscall state, and kernel wait-channel information.

The reviewed scripts do not intentionally read:

- `/proc/<pid>/environ`
- `/proc/<pid>/cmdline`

This does not mean diagnostic output is guaranteed to contain no sensitive
information. Process identifiers, process metadata, filesystem paths, device
names, and system characteristics may still be sensitive in some environments.

The project's own configuration variables, including `LPD_*` variables, may
be read to configure collection behavior. This is distinct from collecting
the environment of a process being diagnosed.

## 2. Subprocess Execution Boundaries

External commands are executed through the shared helper in
`scripts/common.py`.

The helper applies the following controls:

- Commands are supplied as argument arrays rather than shell command strings.
- External processes are launched from an argument list with `shell=False`.
- Empty arguments, invalid argument types, and NUL-containing arguments
  are rejected.
- Known privilege-escalation executables are blocked.
- Configured mutating subcommands can be rejected.
- Standard output and standard error are captured using bounded streaming.
- Output size and execution time are limited.
- Each child starts in a separate process session.
- Timeout and output-limit violations trigger process-group cleanup.
- Cleanup attempts SIGTERM first and escalates to SIGKILL when necessary.

### Process Termination Boundary

The process-group cleanup mechanism terminates subprocesses launched by the
diagnostic runner.

It is not intended to terminate the application PID being investigated.

The use of `os.kill`, `os.killpg`, SIGTERM, and SIGKILL in the shared helper
is part of subprocess lifecycle management, not an operation that passive
diagnostics perform against monitored application processes.

## 3. Credential and Private-Key Redaction

The shared credential scrubber in `scripts/common.py` provides
pattern-based redaction for common sensitive values.

Its supported patterns include:

- PEM private-key blocks, including mismatched and incomplete blocks.
- Database connection-string passwords.
- Authorization headers and bearer tokens.
- AWS access-key identifiers and secret assignments.
- GitHub access tokens.
- OpenAI and other API-key formats covered by the configured patterns.
- Stripe, Google Cloud, Slack, and SendGrid token patterns.
- Docker registry authentication and Docker login passwords.
- Redis passwords and Azure account keys.
- Generic password, secret, token, API-key, and private-key assignments.
- Common command-line password and token arguments.
- Secret values stored in recursively processed dictionaries and lists.

### Current Redaction Integration

The reviewed implementation applies shared redaction in these paths:

- `scripts/profile_process.sh` recursively scrubs its normal final JSON
  payload. Its early argument and validation errors use a separate direct
  error emitter and are not covered by that final-payload scrubber.
- `scripts/generate_report.py` scrubs generated report objects and Markdown
  output.
- Shared error handling applies text redaction to the error messages it
  processes.

### Redaction Limitations

Redaction is best-effort, not a complete data-loss-prevention system.

Pattern-based detection can miss:

- New or unsupported credential formats.
- Encoded, encrypted, obfuscated, or fragmented secrets.
- Secret values without recognizable names or formats.
- Credentials embedded in arbitrary free-form text.
- Sensitive information not covered by the configured patterns.

Not every standalone collector routes its output through the shared
credential scrubber. Several collectors emit JSON directly.

Therefore, users must not assume that every standalone collector output,
terminal log, or generated artifact is automatically sanitized.

Review diagnostic output before storing it in shared locations, attaching it
to public issues, or sending it to third parties.

## 4. Diagnostic Data and Privacy

Diagnostic output is intended to contain operational telemetry rather than
application secrets.

Depending on the selected collector, reports can contain:

- Process identifiers and process-related metrics.
- CPU, memory, disk, and network measurements.
- Kernel and cgroup information.
- Device, interface, and filesystem identifiers.
- Kernel paths and diagnostic warnings.
- Active profiler summaries when explicitly requested.

Some of this information can reveal details about infrastructure,
application behavior, or internal system topology.

Before sharing a report:

1. Review the complete report and its warnings.
2. Remove private hostnames, IP addresses, identifiers, and paths where
   necessary.
3. Check for credentials and application-specific sensitive information.
4. Do not publish raw diagnostic output when it could expose internal
   infrastructure details.

## 5. Permission and Capability Boundaries

Linux permissions, namespaces, container configuration, kernel versions,
and available capabilities affect which telemetry can be collected.

The tool does not automatically bypass these restrictions.

Optional tools such as `perf`, `strace`, `ss`, `iostat`, `vmstat`, `pidstat`,
and `bpftool` may be unavailable or restricted.

A successful diagnostic run does not imply that every subsystem was
fully inspected. Review collection warnings and capability information
when interpreting the results.

## 6. Security Reporting

Please report suspected vulnerabilities through the repository's private
GitHub vulnerability reporting or Security Advisories mechanism.

Do not publish exploitable vulnerability details, credentials, private keys,
or sensitive diagnostic logs in public issues.

See the repository root `SECURITY.md` for supported versions and reporting
instructions.

## 7. Security Scope

This project is a diagnostic tool, not a complete host security scanner,
secret-management system, or isolation boundary.

Its read-only defaults, subprocess controls, explicit active-profiling
consent, and credential-redaction mechanisms reduce operational risk.
They do not eliminate risks arising from compromised hosts, untrusted
executables, malicious diagnostic inputs, kernel vulnerabilities, or
sensitive information present in collected telemetry.

Users remain responsible for reviewing permissions, authorizing active
profiling, protecting generated reports, and validating the security of
their execution environment.
