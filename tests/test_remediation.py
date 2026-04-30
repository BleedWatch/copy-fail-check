import importlib.util
import contextlib
import io
import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock


ROOT = os.path.dirname(os.path.dirname(__file__))
SPEC = importlib.util.spec_from_file_location("copy_fail_check", os.path.join(ROOT, "copy-fail-check.py"))
cfc = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cfc)


class RemediationTests(unittest.TestCase):
    def make_root(self):
        temp = tempfile.TemporaryDirectory(prefix="copy-fail-remediate-", dir="/tmp")
        root = temp.name
        os.makedirs(os.path.join(root, "etc", "modprobe.d"), exist_ok=True)
        os.makedirs(os.path.join(root, "proc"), exist_ok=True)
        os.makedirs(os.path.join(root, "var", "log"), exist_ok=True)
        with open(os.path.join(root, "etc", "os-release"), "w", encoding="utf-8") as handle:
            handle.write('ID=ubuntu\nVERSION_ID="24.04"\nID_LIKE=debian\n')
        with open(os.path.join(root, "proc", "version"), "w", encoding="utf-8") as handle:
            handle.write("Linux version 6.6.0 test\n")
        with open(os.path.join(root, "proc", "modules"), "w", encoding="utf-8") as handle:
            handle.write("")
        return temp

    def fake_run(self, calls):
        def run(command, check=False, timeout=60, capture_output=True, text=True, shell=False):
            calls.append(command)
            return SimpleNamespace(returncode=0, stdout="ok", stderr="")
        return run

    def test_refuses_non_root(self):
        with self.make_root() as root, mock.patch.dict(os.environ, {"BLEEDWATCH_AUTO_CONFIRM": "1"}):
            remediator = cfc.CopyFailRemediator(root=root, euid_func=lambda: 1000)
            code, message = remediator.remediate()
            self.assertEqual(code, cfc.EXIT_REMEDIATION_FAILED)
            self.assertIn("Root", message)

    def test_refuses_negative_confirmation(self):
        with self.make_root() as root:
            remediator = cfc.CopyFailRemediator(root=root, input_func=lambda prompt: "no", euid_func=lambda: 0)
            with contextlib.redirect_stdout(io.StringIO()):
                code, _ = remediator.remediate()
            self.assertEqual(code, cfc.EXIT_REMEDIATION_CANCELLED)

    def test_auto_confirm_idempotence_and_commands(self):
        calls = []
        with self.make_root() as root, mock.patch.dict(os.environ, {"BLEEDWATCH_AUTO_CONFIRM": "1"}):
            remediator = cfc.CopyFailRemediator(
                root=root, subprocess_run=self.fake_run(calls), euid_func=lambda: 0
            )
            code, message = remediator.remediate()
            self.assertEqual(code, cfc.EXIT_REMEDIATED, message)
            mitigation_path = os.path.join(root, "etc", "modprobe.d", "disable-af-alg.conf")
            self.assertTrue(os.path.exists(mitigation_path))
            with open(mitigation_path, encoding="utf-8") as handle:
                first_content = handle.read()

            second = cfc.CopyFailRemediator(root=root, subprocess_run=self.fake_run(calls), euid_func=lambda: 0)
            second_code, second_message = second.remediate()
            self.assertEqual(second_code, cfc.EXIT_REMEDIATED, second_message)
            with open(mitigation_path, encoding="utf-8") as handle:
                second_content = handle.read()
            self.assertEqual(first_content, second_content)
            self.assertTrue(any(action == ["update-initramfs", "-u"] for action in calls))
            self.assertTrue(any(action == ["rmmod", "af_alg"] for action in calls))

    def test_existing_hand_edited_file_is_backed_up(self):
        calls = []
        with self.make_root() as root, mock.patch.dict(os.environ, {"BLEEDWATCH_AUTO_CONFIRM": "1"}):
            mitigation_path = os.path.join(root, "etc", "modprobe.d", "disable-af-alg.conf")
            with open(mitigation_path, "w", encoding="utf-8") as handle:
                handle.write("# local edit\n")
            remediator = cfc.CopyFailRemediator(
                root=root, subprocess_run=self.fake_run(calls), euid_func=lambda: 0
            )
            code, _ = remediator.remediate()
            self.assertEqual(code, cfc.EXIT_REMEDIATED)
            backups = [
                name for name in os.listdir(os.path.dirname(mitigation_path))
                if name.startswith("disable-af-alg.conf.bak.")
            ]
            self.assertTrue(backups)
            self.assertTrue(remediator.warnings)


if __name__ == "__main__":
    unittest.main()
