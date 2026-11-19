# Reproducible Benchmarks (`linux-perf-doctor`)

## Benchmark 1: Live CPU & Process Detection on Linux Sandbox Host
To reproduce a real CPU bottleneck detection on any Linux host without root access:

```bash
# Spawn a controlled 1.5-second Python CPU burner in the background and inspect it:
python3 -c 'import time; t=time.time()+1.5;
while time.time()<t: _ = sum(i*i for i in range(10000))' &
BURNER_PID=$!
python3 scripts/collect_process_metrics.py --pid "$BURNER_PID" --interval 0.3 --pretty
wait "$BURNER_PID" || true
```

## Benchmark 2: Deterministic Saturated Node Fixture Benchmark
To verify cross-subsystem correlation (CFS CPU quota throttling at `35.0%` + `oom_kill=2` + `CLOSE_WAIT=65` + NVMe high write await):

```bash
python3 scripts/generate_report.py \\
  --proc-root tests/fixtures/saturated_node/proc \\
  --cgroup-root tests/fixtures/saturated_node/cgroup \\
  --pid 4242 \\
  --interval 0 \\
  --pretty
```

See `examples/sample-saturated-report.json` and `examples/sample-saturated-report.md` for the exact verified outputs generated from this fixture.

## Recording Terminal Demonstrations
To record a reproducible terminal walkthrough using `asciinema`:
```bash
asciinema rec -i 1.5 demo-linux-perf-doctor.cast
./scripts/check_perf_capabilities.sh --pretty
python3 scripts/generate_report.py --proc-root tests/fixtures/saturated_node/proc --cgroup-root tests/fixtures/saturated_node/cgroup --pid 4242 --interval 0 --format markdown
exit
```
*(Note: No pre-recorded `.cast` or `.gif` binary is bundled in this repository; run the commands above to record on your target host.)*
