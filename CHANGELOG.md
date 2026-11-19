# Changelog

All notable changes to `linux-perf-doctor` are documented in this file.

## [1.0.0] - 2026-11-17
### Added
- Initial release of `linux-perf-doctor` conforming to the Agent Skills Specification.
- Added `scripts/check_perf_capabilities.sh`, `scripts/collect_system_metrics.py`, `scripts/collect_process_metrics.py`, `scripts/inspect_cgroups.py`, `scripts/inspect_network.py`, `scripts/inspect_io.sh`, `scripts/profile_process.sh`, and `scripts/generate_report.py`.
- Added cgroup v1/v2 throttling and OOM event correlation engine.
- Added fixture-backed unit test suite and GitHub Actions CI workflow.
