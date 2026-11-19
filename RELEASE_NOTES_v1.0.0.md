# linux-perf-doctor v1.0.0 — Initial public release

`linux-perf-doctor` is an MIT-licensed Agent Skill for focused engineering analysis. This release publishes the initial toolset, its agent instructions, offline examples, schemas, references, and fixture-backed tests.

## Highlights

- Introduces a read-only Linux telemetry collection workflow built around /proc, /sys, cgroup and PSI data.
- Adds CPU, memory, process, disk I/O, TCP socket and container-throttling diagnostics.
- Adds capability and permission discovery for optional tools such as perf, strace, ss, iostat, vmstat, pidstat and bpftool.
- Adds unified JSON and Markdown diagnostic report generation with measured facts separated from diagnostic hypotheses.
- Keeps active profiling explicitly opt-in and bounded; passive inspection is the default.

## Quick start

Install directly from the public GitHub repository using the Vercel Skills CLI:

```bash
npx skills add AnujTiwari-Student/linux-perf-doctor --skill linux-perf-doctor
```

To install the published v1.0.0 release specifically:

```bash
npx skills add AnujTiwari-Student/linux-perf-doctor@v1.0.0 --skill linux-perf-doctor
```

Alternatively, clone the repository and install from its root directory:

```bash
git clone https://github.com/AnujTiwari-Student/linux-perf-doctor.git
cd linux-perf-doctor
npx skills add . --skill linux-perf-doctor
```

Run the example workflow from the repository root:

```bash
python3 scripts/generate_report.py --pid <PID> --format markdown --output report.md
```

## Validation

The repository includes a GitHub Actions workflow at `.github/workflows/test.yml`. It runs Python syntax checks, validates skill metadata and executable script permissions, and runs the unittest suite. The workflow currently runs on Python 3.11; the project metadata declares Python 3.8 or newer.

## Scope and limitations

- Live collection requires a Linux environment with the relevant procfs/sysfs interfaces.
- Optional profiler tools and permissions affect which diagnostics are available.
- The workflow is read-only by default; active profiling should be used deliberately.

See `README.md`, `SKILL.md`, `docs/`, and `references/` for the full operating model, compatibility notes, security boundaries and examples.

## License

MIT. See [`LICENSE`](LICENSE).
