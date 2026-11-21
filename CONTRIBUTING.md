# Contributing to `linux-perf-doctor`

1. **Standard Library First**: Keep all Python diagnostic scripts compatible with Python 3.8+ standard library (`json`, `os`, `pathlib`, `subprocess`, `argparse`, `unittest`).
2. **Read-Only Safety**: Never add scripts that mutate kernel state (`sysctl -w`), kill processes, or invoke privilege-escalation wrappers.
3. **JSON Envelope Contract**: Every collector script must output valid JSON to `stdout` containing `status`, `timestamp`, `platform`, `tool_versions`, `findings`, `metrics`, `warnings`, `recommendations`, and `errors`.
4. **Tests Required**: Add fixture-backed tests in `tests/test_linux_perf_doctor.py` and verify via `python3 -m unittest discover -s tests -v`.
