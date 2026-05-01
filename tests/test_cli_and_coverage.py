import contextlib
import errno
import importlib.util
import io
import os
import tempfile
import unittest
from unittest import mock


ROOT = os.path.dirname(os.path.dirname(__file__))
SPEC = importlib.util.spec_from_file_location("copy_fail_check", os.path.join(ROOT, "copy-fail-check.py"))
cfc = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cfc)


class FakeSocket:
    def bind(self, address):
        return None

    def close(self):
        return None


class VerdictBranchTests(unittest.TestCase):
    def base_inputs(self):
        host = {"kernel": {"patch_status": "unverified"}}
        checks = {
            "af_alg_syscall": {"status": "accessible"},
            "functional_test": {"status": "not_run"},
            "modules_loaded": [],
            "modprobe_mitigation": {"present": False, "files": [], "completeness": "none", "warnings": []},
            "kernel_patch": {"detected": False, "evidence": None},
        }
        return host, checks

    def test_full_modprobe_mitigation_emits_exit_mitigated(self):
        host, checks = self.base_inputs()
        checks["modprobe_mitigation"] = {"present": True, "files": [], "completeness": "full", "warnings": []}
        detector = cfc.CopyFailDetector(functional_test=False)
        status, vulnerable, code, _, _ = detector.verdict(host, checks)
        self.assertEqual(code, cfc.EXIT_MITIGATED)
        self.assertEqual(status, "mitigated_modprobe")
        self.assertFalse(vulnerable)

    def test_blocked_af_alg_emits_exit_mitigated(self):
        host, checks = self.base_inputs()
        checks["af_alg_syscall"] = {"status": "blocked"}
        detector = cfc.CopyFailDetector(functional_test=False)
        _, _, code, _, _ = detector.verdict(host, checks)
        self.assertEqual(code, cfc.EXIT_MITIGATED)

    def test_unknown_af_alg_status_emits_detection_error(self):
        host, checks = self.base_inputs()
        checks["af_alg_syscall"] = {"status": "error"}
        detector = cfc.CopyFailDetector(functional_test=False)
        status, _, code, _, _ = detector.verdict(host, checks)
        self.assertEqual(code, cfc.EXIT_DETECTION_ERROR)
        self.assertEqual(status, "detection_error")


class EnvironmentErrorTests(unittest.TestCase):
    def test_missing_os_release_yields_runtime_error(self):
        with tempfile.TemporaryDirectory(prefix="copy-fail-env-", dir="/tmp") as root:
            os.makedirs(os.path.join(root, "proc"), exist_ok=True)
            with open(os.path.join(root, "proc", "version"), "w", encoding="utf-8") as handle:
                handle.write("Linux version 6.6.0\n")
            detector = cfc.CopyFailDetector(root=root, functional_test=False)
            result = detector.detect()
            self.assertEqual(result["verdict"]["exit_code"], cfc.EXIT_RUNTIME_ERROR)
            self.assertTrue(result["checks"]["environment"]["errors"])

    def test_alpine_is_unsupported(self):
        with tempfile.TemporaryDirectory(prefix="copy-fail-env-", dir="/tmp") as root:
            os.makedirs(os.path.join(root, "proc"), exist_ok=True)
            os.makedirs(os.path.join(root, "etc"), exist_ok=True)
            with open(os.path.join(root, "etc", "os-release"), "w", encoding="utf-8") as handle:
                handle.write('ID=alpine\nVERSION_ID="3.19"\n')
            with open(os.path.join(root, "proc", "version"), "w", encoding="utf-8") as handle:
                handle.write("Linux version 6.6.0\n")
            detector = cfc.CopyFailDetector(root=root, functional_test=False)
            result = detector.detect()
            self.assertEqual(result["verdict"]["exit_code"], cfc.EXIT_RUNTIME_ERROR)
            self.assertTrue(any("unsupported" in err.lower() for err in result["checks"]["environment"]["errors"]))


class ArgparseAndOutputTests(unittest.TestCase):
    def test_modes_are_mutually_exclusive(self):
        parser = cfc.build_parser()
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            parser.parse_args(["--check", "--remediate"])

    def test_version_flag_prints_and_exits_zero(self):
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            code = cfc.main(["--version"])
        self.assertEqual(code, cfc.EXIT_SAFE)
        self.assertIn(cfc.VERSION, buf.getvalue())

    def test_quiet_suppresses_output(self):
        with mock.patch.object(cfc.socket, "socket", side_effect=OSError(errno.EAFNOSUPPORT, "blocked")):
            with contextlib.redirect_stdout(io.StringIO()) as buf:
                code = cfc.main(["--check", "--quiet"])
        self.assertIn(code, (cfc.EXIT_SAFE, cfc.EXIT_MITIGATED, cfc.EXIT_VULNERABLE,
                             cfc.EXIT_DETECTION_ERROR, cfc.EXIT_RUNTIME_ERROR))
        self.assertEqual(buf.getvalue(), "")

    def test_no_color_env_disables_color(self):
        result = cfc.CopyFailDetector(functional_test=False).build_result(
            cfc.utc_now_z(),
            {"hostname": "h", "os": {"distro": "ubuntu", "version": "24.04", "family": "debian"},
             "kernel": {"version": "6.6", "patch_status": "unverified"}},
            {"environment": {"status": "ok", "errors": []},
             "af_alg_syscall": {"status": "accessible", "errno": None, "detail": ""},
             "functional_test": {"status": "not_run", "detail": ""},
             "modules_loaded": [],
             "modprobe_mitigation": {"present": False, "files": [], "completeness": "none", "warnings": []},
             "kernel_patch": {"detected": False, "evidence": None, "weak_evidence": None}},
            "unverified", False, cfc.EXIT_UNVERIFIED, "unverified", []
        )
        colored = cfc.make_human(result, use_color=True)
        plain = cfc.make_human(result, use_color=False)
        self.assertIn("\033[", colored)
        self.assertNotIn("\033[", plain)

    def test_output_file_writes_to_path(self):
        with tempfile.NamedTemporaryFile(mode="r", delete=False, dir="/tmp",
                                         prefix="copy-fail-out-", suffix=".json") as out:
            out_path = out.name
        try:
            with mock.patch.object(cfc.socket, "socket", side_effect=OSError(errno.EAFNOSUPPORT, "blocked")):
                code = cfc.main(["--check", "--json", "--output-file", out_path])
            self.assertIsInstance(code, int)
            with open(out_path, "r", encoding="utf-8") as handle:
                payload = handle.read()
            import json as _json
            data = _json.loads(payload)
            self.assertEqual(data["tool"], cfc.TOOL_NAME)
        finally:
            try:
                os.unlink(out_path)
            except OSError:
                pass

    def test_sarif_safe_state_is_parseable(self):
        result = cfc.CopyFailDetector(functional_test=False).build_result(
            cfc.utc_now_z(),
            {"hostname": "h", "os": {}, "kernel": {"version": "6.15", "patch_status": "patched"}},
            {"environment": {"status": "ok", "errors": []},
             "af_alg_syscall": {"status": "accessible", "errno": None, "detail": ""},
             "functional_test": {"status": "no_modification", "detail": ""},
             "modules_loaded": [],
             "modprobe_mitigation": {"present": False, "files": [], "completeness": "none", "warnings": []},
             "kernel_patch": {"detected": True, "evidence": "patch", "weak_evidence": None}},
            "patched", False, cfc.EXIT_SAFE, "ok", []
        )
        import json as _json
        sarif = _json.loads(cfc.make_sarif(result))
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(sarif["runs"][0]["results"], [])


class RemediationOrderTests(unittest.TestCase):
    def test_root_check_runs_before_confirmation_prompt(self):
        prompts = []

        def record_prompt(prompt):
            prompts.append(prompt)
            return "CONFIRM"

        with tempfile.TemporaryDirectory(prefix="copy-fail-order-", dir="/tmp") as root:
            os.makedirs(os.path.join(root, "etc", "modprobe.d"), exist_ok=True)
            remediator = cfc.CopyFailRemediator(root=root, input_func=record_prompt, euid_func=lambda: 1000)
            code, _ = remediator.remediate()
            self.assertEqual(code, cfc.EXIT_REMEDIATION_FAILED)
            self.assertEqual(prompts, [])


if __name__ == "__main__":
    unittest.main()
