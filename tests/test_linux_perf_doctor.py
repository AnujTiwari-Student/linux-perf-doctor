import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "saturated_node"
CGROUP_V1_DIR = REPO_ROOT / "tests" / "fixtures" / "cgroup_v1_node" / "cgroup"
SCHEMA_PATH = REPO_ROOT / "schemas" / "diagnostic-output.schema.json"

sys.path.insert(0, str(SCRIPTS_DIR))
import collect_process_metrics
import collect_system_metrics
import generate_report
import inspect_cgroups
import inspect_network
from common import decode_cap_eff_hex, run_bounded_command, validate_against_schema


class TestLinuxPerfDoctor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    def assertValidSchema(self, payload):
        errs = validate_against_schema(payload, self.schema)
        self.assertEqual(errs, [], f"JSON Schema validation errors: {errs}")

    def test_capabilities_script_json_schema_and_bitmask(self):
        proc = subprocess.run([str(SCRIPTS_DIR / "check_perf_capabilities.sh")], capture_output=True, text=True, timeout=10)
        self.assertEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertValidSchema(data)
        self.assertIn("capabilities", data["metrics"])
        self.assertIn("CAP_PERFMON", data["metrics"]["capabilities"]["capabilities"])
        self.assertIn("CAP_SYS_PTRACE", data["metrics"]["capabilities"]["capabilities"])
        self.assertIn("CAP_BPF", data["metrics"]["capabilities"]["capabilities"])

    def test_cap_eff_bitmask_decoding_unit(self):
        # Bit 19 (CAP_SYS_PTRACE) + Bit 38 (CAP_PERFMON) + Bit 39 (CAP_BPF)
        mask = (1 << 19) | (1 << 38) | (1 << 39)
        decoded = decode_cap_eff_hex(f"{mask:016x}")
        self.assertTrue(decoded["valid"])
        caps = decoded["capabilities"]
        self.assertTrue(caps["CAP_SYS_PTRACE"])
        self.assertTrue(caps["CAP_PERFMON"])
        self.assertTrue(caps["CAP_BPF"])
        self.assertFalse(caps["CAP_SYS_ADMIN"])

    def test_bounded_subprocess_truncation_and_sudo_rejection(self):
        res_sudo = run_bounded_command(["sudo", "id"])
        self.assertFalse(res_sudo["ok"])
        self.assertIn("privilege escalation", res_sudo["stderr"])

        res_trunc = run_bounded_command([sys.executable, "-c", "print('A' * 10000)"], max_bytes=512)
        self.assertTrue(res_trunc["ok"])
        self.assertTrue(res_trunc["truncated"])
        self.assertEqual(len(res_trunc["stdout"]), 512)

    def test_system_metrics_saturated_fixture_and_schema(self):
        res = collect_system_metrics.collect_system_metrics(FIXTURE_DIR / "proc", interval=0.0, samples=1)
        self.assertValidSchema(res)
        self.assertIn(res["status"], ("warning", "critical"))
        ids = {f["id"] for f in res["findings"]}
        self.assertIn("SYS-CPU-001", ids)
        self.assertIn("SYS-MEM-001", ids)
        self.assertIn("SYS-MEM-002", ids)
        self.assertIn("SYS-IO-001", ids)
        self.assertEqual(res["metrics"]["metric_semantics"]["cpu"], "cumulative_since_boot")

    def test_process_metrics_d_state_and_sched_fixture(self):
        res = collect_process_metrics.inspect_single_pid(FIXTURE_DIR / "proc", 4242, interval=0.0)
        self.assertValidSchema(res)
        self.assertEqual(res["status"], "warning")
        ids = {f["id"] for f in res["findings"]}
        self.assertIn("PROC-STATE-001", ids)
        self.assertIn("PROC-SCHED-001", ids)
        self.assertIn("PROC-MEM-001", ids)
        self.assertEqual(res["metrics"]["scheduler"]["nr_migrations"], 1840)
        self.assertAlmostEqual(res["metrics"]["scheduler"]["runqueue_wait_sum_ms"], 18450.25)

    def test_cgroup_v2_throttling_oom_and_psi_fixture(self):
        res = inspect_cgroups.inspect_cgroups(FIXTURE_DIR / "cgroup")
        self.assertValidSchema(res)
        self.assertEqual(res["status"], "critical")
        ids = {f["id"] for f in res["findings"]}
        self.assertIn("CGRP-CPU-001", ids)
        self.assertIn("CGRP-MEM-001", ids)
        self.assertIn("CGRP-PSI-001", ids)
        self.assertAlmostEqual(res["metrics"]["cpu"]["throttle_pct"], 35.0)
        self.assertAlmostEqual(res["metrics"]["pressure"]["io"]["full"]["avg10"], 31.4)

    def test_cgroup_v1_fixture_and_schema(self):
        res = inspect_cgroups.inspect_cgroups(CGROUP_V1_DIR)
        self.assertValidSchema(res)
        self.assertEqual(res["metrics"]["cgroup_version"], "v1")
        self.assertEqual(res["status"], "critical")
        ids = {f["id"] for f in res["findings"]}
        self.assertIn("CGRP-CPU-001", ids)
        self.assertIn("CGRP-MEM-001", ids)
        self.assertAlmostEqual(res["metrics"]["cpu"]["throttle_pct"], 30.0)
        self.assertEqual(res["metrics"]["memory"]["failcnt"], 142)

    def test_network_snmp_netstat_close_wait_and_queues_fixture(self):
        res = inspect_network.inspect_network(FIXTURE_DIR / "proc")
        self.assertValidSchema(res)
        self.assertIn(res["status"], ("warning", "critical"))
        ids = {f["id"] for f in res["findings"]}
        self.assertIn("NET-TCP-001", ids)
        self.assertIn("NET-SNMP-RETRANS", ids)
        self.assertIn("NET-SNMP-UDPBUF", ids)
        self.assertIn("NET-NETSTAT-LISTEN", ids)
        self.assertIn("NET-QUEUE-001", ids)
        self.assertIn("NET-IFACE-001", ids)
        self.assertEqual(res["metrics"]["netstat"]["TcpExt"]["ListenOverflows"], 340)

    def test_inspect_io_script_cumulative_and_interval_modes(self):
        proc = subprocess.run(
            [str(SCRIPTS_DIR / "inspect_io.sh"), "--proc-root", str(FIXTURE_DIR / "proc"), "--interval", "0.05"],
            capture_output=True, text=True, timeout=10
        )
        self.assertEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertValidSchema(data)
        self.assertEqual(data["status"], "warning")
        self.assertEqual(data["metrics"]["metric_semantics"]["interval_delta"], "interval_derived")
        self.assertIn("interval_delta", data["metrics"]["block_devices"][0])

    def test_active_profiling_requires_opt_in_and_returns_valid_error_schema(self):
        proc = subprocess.run(
            [str(SCRIPTS_DIR / "profile_process.sh"), "--pid", "1", "--mode", "strace-summary"],
            capture_output=True, text=True, timeout=10
        )
        self.assertEqual(proc.returncode, 2)
        err = json.loads(proc.stderr)
        self.assertValidSchema(err)
        self.assertEqual(err["status"], "error")

    def test_error_handling_and_boundary_conditions(self):
        res = collect_system_metrics.collect_system_metrics(Path("/nonexistent/proc/path"), interval=0.0, samples=1)
        self.assertValidSchema(res)
        self.assertEqual(res["status"], "error")

        proc_bad = subprocess.run(
            [sys.executable, str(SCRIPTS_DIR / "collect_system_metrics.py"), "--interval", "999"],
            capture_output=True, text=True, timeout=5
        )
        self.assertEqual(proc_bad.returncode, 2)
        self.assertValidSchema(json.loads(proc_bad.stderr))

    def test_unified_report_correlation_hypothesis_and_schema(self):
        rep = generate_report.build_unified_report(FIXTURE_DIR / "proc", FIXTURE_DIR / "cgroup", 4242, interval=0.0)
        self.assertValidSchema(rep)
        self.assertEqual(rep["status"], "critical")
        ids = {f["id"] for f in rep["findings"]}
        self.assertIn("HYP-CGRP-QUOTA", ids)
        md = generate_report.render_markdown(rep)
        self.assertIn("# Linux Performance Diagnostic Report", md)
        self.assertIn("HYP-CGRP-QUOTA", md)


    def test_streaming_bounded_subprocess_large_stdout_and_process_termination(self):
        import os as _os
        res = run_bounded_command(
            [sys.executable, "-c", "import time\nwhile True:\n    print('X' * 4096, flush=True)"],
            timeout_sec=5.0,
            max_bytes=8192,
        )
        self.assertTrue(res["ok"])
        self.assertTrue(res["truncated"])
        self.assertTrue(res["stdout_truncated"])
        self.assertEqual(res["terminated_reason"], "output_limit_exceeded")
        self.assertLessEqual(len(res["stdout"].encode("utf-8")), 8192)
        self.assertIsNotNone(res["child_pid"])
        with self.assertRaises(ProcessLookupError):
            _os.kill(res["child_pid"], 0)

    def test_streaming_bounded_subprocess_large_stderr_and_simultaneous_io(self):
        res_err = run_bounded_command(
            [sys.executable, "-c", "import sys\nfor _ in range(500):\n    sys.stderr.write('E' * 512)\n    sys.stderr.flush()"],
            timeout_sec=5.0,
            max_bytes=4096,
        )
        self.assertTrue(res_err["truncated"])
        self.assertTrue(res_err["stderr_truncated"])
        self.assertLessEqual(len(res_err["stderr"].encode("utf-8")), 4096)

        res_both = run_bounded_command(
            [sys.executable, "-c", "import sys\nfor _ in range(100):\n    sys.stdout.write('O' * 200)\n    sys.stderr.write('E' * 200)\n    sys.stdout.flush()\n    sys.stderr.flush()"],
            timeout_sec=5.0,
            max_bytes=4096,
        )
        self.assertTrue(res_both["truncated"])
        self.assertLessEqual(len(res_both["stdout"].encode("utf-8")), 4096)
        self.assertLessEqual(len(res_both["stderr"].encode("utf-8")), 4096)

    def test_streaming_bounded_subprocess_timeout_missing_exec_and_unsafe_args(self):
        import os as _os
        res_to = run_bounded_command(
            [sys.executable, "-c", "import time; time.sleep(10)"],
            timeout_sec=0.25,
            max_bytes=4096,
        )
        self.assertFalse(res_to["ok"])
        self.assertTrue(res_to["timed_out"])
        self.assertTrue(res_to["truncated"])
        self.assertEqual(res_to["terminated_reason"], "timeout")
        with self.assertRaises(ProcessLookupError):
            _os.kill(res_to["child_pid"], 0)

        res_missing = run_bounded_command(["/nonexistent_binary_xyz_12345"])
        self.assertFalse(res_missing["ok"])
        self.assertEqual(res_missing["returncode"], 127)
        self.assertEqual(res_missing["terminated_reason"], "executable_not_found")

        res_unsafe = run_bounded_command(["python3", "arg_with_\x00_null"])
        self.assertFalse(res_unsafe["ok"])
        self.assertEqual(res_unsafe["terminated_reason"], "invalid_arguments")

        for priv_bin in ("sudo", "su", "pkexec"):
            res_priv = run_bounded_command([priv_bin, "id"])
            self.assertFalse(res_priv["ok"])
            self.assertEqual(res_priv["terminated_reason"], "blocked_privilege_escalation")



    @staticmethod
    def _cleanup_subprocess_test_processes(res, grandchild_pid, marker_path):
        import os as _os
        import signal as _signal
        from common import _reap_process_group

        if grandchild_pid is None and marker_path is not None and marker_path.exists():
            try:
                raw_pid = marker_path.read_text(encoding="utf-8").strip()
                if raw_pid.isdigit():
                    grandchild_pid = int(raw_pid)
            except Exception:
                pass

        if grandchild_pid is None and isinstance(res, dict):
            stdout_txt = res.get("stdout") or ""
            for line in stdout_txt.splitlines():
                if line.startswith("GRANDCHILD_PID="):
                    val = line.split("=", 1)[1].strip()
                    if val.isdigit():
                        grandchild_pid = int(val)
                        break

        child_pid = res.get("child_pid") if isinstance(res, dict) else None
        if child_pid:
            for sig in (_signal.SIGKILL,):
                try:
                    _os.killpg(child_pid, sig)
                except Exception:
                    pass
                try:
                    _os.kill(child_pid, sig)
                except Exception:
                    pass
            try:
                _reap_process_group(child_pid)
            except Exception:
                pass

        if grandchild_pid:
            try:
                _os.killpg(grandchild_pid, _signal.SIGKILL)
            except Exception:
                pass
            try:
                _os.kill(grandchild_pid, _signal.SIGKILL)
            except Exception:
                pass
            try:
                _os.waitpid(grandchild_pid, _os.WNOHANG)
            except Exception:
                pass

    def test_bug1_descendant_ignoring_sigterm_killed_on_output_limit(self):
        import os as _os
        import tempfile as _tempfile
        from common import is_pid_alive

        with _tempfile.TemporaryDirectory() as tmpdir:
            marker_path = Path(tmpdir) / "grandchild_limit.pid"
            script = (
                "import os, signal, subprocess, sys, time\n"
                "marker_str = sys.argv[1]\n"
                "tmp_str = marker_str + '.tmp'\n"
                "if hasattr(os, 'fork'):\n"
                "    r_fd, w_fd = os.pipe()\n"
                "    pid = os.fork()\n"
                "    if pid == 0:\n"
                "        os.close(r_fd)\n"
                "        signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                "        os.write(w_fd, b'READY\\n')\n"
                "        os.close(w_fd)\n"
                "        while True:\n"
                "            time.sleep(1.0)\n"
                "    os.close(w_fd)\n"
                "    os.read(r_fd, 16)\n"
                "    os.close(r_fd)\n"
                "    gpid = pid\n"
                "else:\n"
                "    child = subprocess.Popen([sys.executable, '-c', "
                "'import signal, sys, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); sys.stdout.write(\"READY\\n\"); sys.stdout.flush(); time.sleep(60)'], "
                "stdout=subprocess.PIPE, text=True)\n"
                "    child.stdout.readline()\n"
                "    gpid = child.pid\n"
                "with open(tmp_str, 'w', encoding='utf-8') as f:\n"
                "    f.write(f'{gpid}\\n')\n"
                "    f.flush()\n"
                "os.replace(tmp_str, marker_str)\n"
                "sys.stdout.write(f'GRANDCHILD_PID={gpid}\\n')\n"
                "sys.stdout.flush()\n"
                "chunk = 'Z' * 4096\n"
                "while True:\n"
                "    sys.stdout.write(chunk)\n"
                "    sys.stdout.flush()\n"
                "    time.sleep(0.01)\n"
            )
            res = None
            grandchild_pid = None
            try:
                res = run_bounded_command(
                    [sys.executable, "-c", script, str(marker_path)],
                    timeout_sec=5.0,
                    max_bytes=4096,
                    ready_file=marker_path,
                )
                if marker_path.exists():
                    grandchild_pid = int(marker_path.read_text(encoding="utf-8").strip())
                self.assertTrue(marker_path.exists(), "Deterministic startup marker file was not written")
                self.assertIsNotNone(grandchild_pid)
                self.assertGreater(grandchild_pid, 0)
                self.assertTrue(res["truncated"])
                self.assertTrue(res["stdout_truncated"])
                self.assertEqual(res["terminated_reason"], "output_limit_exceeded")
                self.assertIn(f"GRANDCHILD_PID={grandchild_pid}", res["stdout"])
                self.assertFalse(is_pid_alive(res["child_pid"]))
                self.assertFalse(is_pid_alive(grandchild_pid))
                with self.assertRaises(ProcessLookupError):
                    _os.kill(grandchild_pid, 0)
            finally:
                self._cleanup_subprocess_test_processes(res, grandchild_pid, marker_path)

    def test_bug1_descendant_ignoring_sigterm_killed_on_timeout(self):
        import os as _os
        import tempfile as _tempfile
        from common import is_pid_alive

        with _tempfile.TemporaryDirectory() as tmpdir:
            marker_path = Path(tmpdir) / "grandchild_timeout.pid"
            script = (
                "import os, signal, subprocess, sys, time\n"
                "marker_str = sys.argv[1]\n"
                "tmp_str = marker_str + '.tmp'\n"
                "if hasattr(os, 'fork'):\n"
                "    r_fd, w_fd = os.pipe()\n"
                "    pid = os.fork()\n"
                "    if pid == 0:\n"
                "        os.close(r_fd)\n"
                "        signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                "        os.write(w_fd, b'READY\\n')\n"
                "        os.close(w_fd)\n"
                "        while True:\n"
                "            time.sleep(1.0)\n"
                "    os.close(w_fd)\n"
                "    os.read(r_fd, 16)\n"
                "    os.close(r_fd)\n"
                "    gpid = pid\n"
                "else:\n"
                "    child = subprocess.Popen([sys.executable, '-c', "
                "'import signal, sys, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); sys.stdout.write(\"READY\\n\"); sys.stdout.flush(); time.sleep(60)'], "
                "stdout=subprocess.PIPE, text=True)\n"
                "    child.stdout.readline()\n"
                "    gpid = child.pid\n"
                "with open(tmp_str, 'w', encoding='utf-8') as f:\n"
                "    f.write(f'{gpid}\\n')\n"
                "    f.flush()\n"
                "os.replace(tmp_str, marker_str)\n"
                "sys.stdout.write(f'GRANDCHILD_PID={gpid}\\n')\n"
                "sys.stdout.flush()\n"
                "time.sleep(60.0)\n"
            )
            res = None
            grandchild_pid = None
            try:
                res = run_bounded_command(
                    [sys.executable, "-c", script, str(marker_path)],
                    timeout_sec=0.4,
                    max_bytes=4096,
                    ready_file=marker_path,
                    startup_timeout_sec=10.0,
                )
                if marker_path.exists():
                    grandchild_pid = int(marker_path.read_text(encoding="utf-8").strip())
                self.assertTrue(marker_path.exists(), "Descendant did not complete readiness handshake before timeout")
                self.assertIsNotNone(grandchild_pid)
                self.assertGreater(grandchild_pid, 0)
                self.assertFalse(res["ok"])
                self.assertTrue(res["timed_out"])
                self.assertTrue(res["truncated"])
                self.assertEqual(res["terminated_reason"], "timeout")
                self.assertIn(f"GRANDCHILD_PID={grandchild_pid}", res["stdout"])
                self.assertFalse(is_pid_alive(res["child_pid"]))
                self.assertFalse(is_pid_alive(grandchild_pid))
                with self.assertRaises(ProcessLookupError):
                    _os.kill(grandchild_pid, 0)
            finally:
                self._cleanup_subprocess_test_processes(res, grandchild_pid, marker_path)

    def test_bug1_parent_exits_on_sigterm_while_descendant_ignores_sigterm(self):
        import os as _os
        import tempfile as _tempfile
        from common import is_pid_alive

        with _tempfile.TemporaryDirectory() as tmpdir:
            marker_path = Path(tmpdir) / "grandchild_parent_exit.pid"
            script = (
                "import os, signal, sys, time\n"
                "marker_str = sys.argv[1]\n"
                "tmp_str = marker_str + '.tmp'\n"
                "signal.signal(signal.SIGTERM, lambda s, f: os._exit(0))\n"
                "r_fd, w_fd = os.pipe()\n"
                "pid = os.fork()\n"
                "if pid == 0:\n"
                "    os.close(r_fd)\n"
                "    signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                "    os.write(w_fd, b'READY\\n')\n"
                "    os.close(w_fd)\n"
                "    while True:\n"
                "        time.sleep(1.0)\n"
                "os.close(w_fd)\n"
                "os.read(r_fd, 16)\n"
                "os.close(r_fd)\n"
                "with open(tmp_str, 'w', encoding='utf-8') as f:\n"
                "    f.write(f'{pid}\\n')\n"
                "    f.flush()\n"
                "os.replace(tmp_str, marker_str)\n"
                "sys.stdout.write(f'GRANDCHILD_PID={pid}\\n')\n"
                "sys.stdout.flush()\n"
                "time.sleep(60.0)\n"
            )
            res = None
            grandchild_pid = None
            try:
                res = run_bounded_command(
                    [sys.executable, "-c", script, str(marker_path)],
                    timeout_sec=0.4,
                    max_bytes=4096,
                    ready_file=marker_path,
                    startup_timeout_sec=10.0,
                )
                if marker_path.exists():
                    grandchild_pid = int(marker_path.read_text(encoding="utf-8").strip())
                self.assertTrue(marker_path.exists(), "Descendant did not complete readiness handshake before timeout")
                self.assertIsNotNone(grandchild_pid)
                self.assertGreater(grandchild_pid, 0)
                self.assertTrue(res["timed_out"])
                self.assertEqual(res["terminated_reason"], "timeout")
                self.assertIn(f"GRANDCHILD_PID={grandchild_pid}", res["stdout"])
                self.assertFalse(is_pid_alive(res["child_pid"]))
                self.assertFalse(is_pid_alive(grandchild_pid))
                with self.assertRaises(ProcessLookupError):
                    _os.kill(grandchild_pid, 0)
            finally:
                self._cleanup_subprocess_test_processes(res, grandchild_pid, marker_path)



    def test_diagnostic_report_and_error_envelope_redact_credentials_and_pem_keys(self):
        from common import make_error_envelope, scrub_object_secrets
        err = make_error_envelope('Failed with PASSWORD="super secret value" and -----BEGIN RSA PRIVATE KEY-----\nAQID\n')
        self.assertValidSchema(err)
        dumped_err = json.dumps(err)
        self.assertNotIn("super secret value", dumped_err)
        self.assertNotIn("AQID", dumped_err)
        self.assertIn("[REDACTED_SECRET]", dumped_err)
        self.assertIn("[REDACTED_PRIVATE_KEY]", dumped_err)

        rep = generate_report.build_unified_report(FIXTURE_DIR / "proc", FIXTURE_DIR / "cgroup", 4242, interval=0.0)
        rep["warnings"].append(' token="my multiword secret token" ')
        scrubbed_rep = scrub_object_secrets(rep)
        md = generate_report.render_markdown(scrubbed_rep)
        self.assertNotIn("multiword secret token", md)

if __name__ == "__main__":
    unittest.main()
