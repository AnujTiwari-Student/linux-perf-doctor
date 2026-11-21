# Changelog

All notable changes to `linux-perf-doctor` are documented in this file.

## [1.0.0] - 2026-11-17
### Added
- Initial release of `linux-perf-doctor` conforming to the Agent Skills Specification.
- Added `scripts/check_perf_capabilities.sh`, `scripts/collect_system_metrics.py`, `scripts/collect_process_metrics.py`, `scripts/inspect_cgroups.py`, `scripts/inspect_network.py`, `scripts/inspect_io.sh`, `scripts/profile_process.sh`, and `scripts/generate_report.py`.
- Added cgroup v1/v2 throttling and OOM event correlation engine.
- Added fixture-backed unit test suite and GitHub Actions CI workflow.

## [1.0.1] - 2026-11-20
- Replaced executable blocklist with a strict reviewed executable allowlist and `shutil.which` path resolution.
- Refactored shell wrappers (`check_perf_capabilities.sh`, `inspect_io.sh`, `profile_process.sh`) to pass CLI parameters via positional `sys.argv` instead of exporting environment variables.
- Detached child stdin (`DEVNULL`), added minimal allowlisted child environment builder, centralized test CLI calls through `run_bounded_command()`, and updated security docs.
