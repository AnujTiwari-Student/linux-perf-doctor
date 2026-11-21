import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import common  # noqa: E402


class TestSkillScriptLauncher(unittest.TestCase):
    def _make(self, directory, name, mode):
        path = Path(directory) / name
        path.write_text("#!/bin/sh\necho launched\n")
        os.chmod(path, mode)
        return path

    def test_non_executable_bundled_script_runs_through_shell(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = self._make(tmp, "inspect_io.sh", 0o644)
            with mock.patch.object(common, "_SKILL_SCRIPT_DIR", Path(tmp).resolve()):
                res = common.run_bounded_command([str(script)], allowed_executables={"inspect_io.sh"})
            self.assertTrue(res["ok"], res)
            self.assertIn("launched", res["stdout"])

    def test_executable_script_is_not_wrapped(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = self._make(tmp, "inspect_io.sh", 0o755)
            with mock.patch.object(common, "_SKILL_SCRIPT_DIR", Path(tmp).resolve()):
                self.assertEqual(common._skill_script_launcher(str(script)), [])

    def test_unlisted_script_name_is_not_wrapped(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = self._make(tmp, "other_tool.sh", 0o644)
            with mock.patch.object(common, "_SKILL_SCRIPT_DIR", Path(tmp).resolve()):
                self.assertEqual(common._skill_script_launcher(str(script)), [])

    def test_script_outside_skill_directory_is_not_wrapped(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = self._make(tmp, "inspect_io.sh", 0o644)
            self.assertEqual(common._skill_script_launcher(str(script)), [])

    def test_symlinked_script_is_not_wrapped(self):
        with tempfile.TemporaryDirectory() as tmp:
            real = self._make(tmp, "real.sh", 0o644)
            link = Path(tmp) / "inspect_io.sh"
            link.symlink_to(real)
            with mock.patch.object(common, "_SKILL_SCRIPT_DIR", Path(tmp).resolve()):
                self.assertEqual(common._skill_script_launcher(str(link)), [])

    def test_shell_is_never_directly_allowlisted(self):
        res = common.run_bounded_command(["bash", "-c", "echo hi"])
        self.assertFalse(res["ok"])
        self.assertEqual(res["terminated_reason"], "blocked_executable")


if __name__ == "__main__":
    unittest.main()
