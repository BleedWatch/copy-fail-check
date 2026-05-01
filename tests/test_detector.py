import errno
import importlib.util
import os
import tempfile
import unittest
from unittest import mock


ROOT = os.path.dirname(os.path.dirname(__file__))
SPEC = importlib.util.spec_from_file_location("copy_fail_check", os.path.join(ROOT, "copy-fail-check.py"))
cfc = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cfc)


class FakeSocket:
    def __init__(self, bind_error=None):
        self.bind_error = bind_error
        self.closed = False

    def bind(self, address):
        if self.bind_error is not None:
            raise self.bind_error

    def close(self):
        self.closed = True


class DetectorTests(unittest.TestCase):
    def make_root(self, os_release, modules=""):
        temp = tempfile.TemporaryDirectory(prefix="copy-fail-test-", dir="/tmp")
        root = temp.name
        os.makedirs(os.path.join(root, "etc", "modprobe.d"), exist_ok=True)
        os.makedirs(os.path.join(root, "proc"), exist_ok=True)
        with open(os.path.join(root, "etc", "os-release"), "w", encoding="utf-8") as handle:
            handle.write(os_release)
        with open(os.path.join(root, "proc", "version"), "w", encoding="utf-8") as handle:
            handle.write("Linux version 6.6.0 test\n")
        with open(os.path.join(root, "proc", "modules"), "w", encoding="utf-8") as handle:
            handle.write(modules)
        return temp

    def test_os_release_supported_families(self):
        cases = {
            "ubuntu": ('ID=ubuntu\nVERSION_ID="24.04"\nID_LIKE=debian\n', "debian"),
            "debian": ('ID=debian\nVERSION_ID="12"\n', "debian"),
            "rhel": ('ID=rhel\nVERSION_ID="9"\nID_LIKE="fedora"\n', "rhel"),
            "suse": ('ID=sles\nVERSION_ID="15"\nID_LIKE="suse"\n', "suse"),
            "amazon": ('ID=amzn\nVERSION_ID="2"\nID_LIKE="centos rhel fedora"\n', "rhel"),
            "alpine": ('ID=alpine\nVERSION_ID="3.19"\n', "unsupported"),
        }
        for name, (content, family) in cases.items():
            with self.subTest(name=name):
                self.assertEqual(cfc.distro_family(cfc.parse_os_release_content(content)), family)

    def test_loaded_module_listing(self):
        modules = "af_alg 32768 1 algif_aead, Live 0x0\nalgif_aead 16384 0 - Live 0x0\nloop 1 0 - Live 0x0\n"
        with self.make_root('ID=ubuntu\nVERSION_ID="24.04"\nID_LIKE=debian\n', modules) as root:
            detector = cfc.CopyFailDetector(root=root, functional_test=False)
            self.assertEqual(detector.list_loaded_modules(), ["af_alg", "algif_aead"])

    def test_modprobe_full_and_partial_detection(self):
        with self.make_root('ID=ubuntu\nVERSION_ID="24.04"\nID_LIKE=debian\n') as root:
            path = os.path.join(root, "etc", "modprobe.d", "disable-af-alg.conf")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("install af_alg /bin/false\nblacklist algif_aead\n")
            detector = cfc.CopyFailDetector(root=root, functional_test=False)
            result = detector.analyze_modprobe()
            self.assertTrue(result["present"])
            self.assertEqual(result["completeness"], "partial")
            self.assertIn("/etc/modprobe.d/disable-af-alg.conf", result["files"])

    def test_af_alg_blocked_by_eafnosupport(self):
        error = OSError(errno.EAFNOSUPPORT, os.strerror(errno.EAFNOSUPPORT))
        with mock.patch.object(cfc.socket, "socket", side_effect=error):
            detector = cfc.CopyFailDetector(functional_test=False)
            self.assertEqual(detector.check_af_alg_syscall()["status"], "blocked")

    def test_af_alg_accessible(self):
        with mock.patch.object(cfc.socket, "socket", return_value=FakeSocket()):
            detector = cfc.CopyFailDetector(functional_test=False)
            self.assertEqual(detector.check_af_alg_syscall()["status"], "accessible")

    def test_functional_test_cleans_sentinel_on_exception(self):
        detector = cfc.CopyFailDetector(tmp_dir="/tmp", functional_test=True)
        sentinel = "/tmp/copy-fail-sentinel-test-{}-cleanup".format(os.getpid())
        if os.path.exists(sentinel):
            os.unlink(sentinel)
        detector.make_sentinel_path = lambda: sentinel
        detector.execute_copy_fail_primitive = mock.Mock(side_effect=OSError(errno.EPERM, "blocked"))
        result = detector.run_functional_test()
        self.assertIn(result["status"], ("error", "setup_failed"))
        self.assertFalse(os.path.exists(sentinel))

    def test_verdict_modification_detected_is_vulnerable_priority(self):
        detector = cfc.CopyFailDetector(functional_test=False)
        host = {"kernel": {"patch_status": "patched"}}
        checks = {
            "af_alg_syscall": {"status": "accessible"},
            "functional_test": {"status": "modification_detected", "detail": "marker landed"},
            "modules_loaded": [],
            "modprobe_mitigation": {"present": True, "files": [], "completeness": "full", "warnings": []},
            "kernel_patch": {"detected": True, "evidence": "changelog references CVE", "weak_evidence": None},
        }
        status, vulnerable, code, _, _ = detector.verdict(host, checks)
        self.assertEqual(code, cfc.EXIT_VULNERABLE)
        self.assertEqual(status, "vulnerable_confirmed_functional")
        self.assertTrue(vulnerable)

    def test_verdict_no_modification_without_evidence_is_unverified_not_patched(self):
        detector = cfc.CopyFailDetector(functional_test=False)
        host = {"kernel": {"patch_status": "unverified"}}
        checks = {
            "af_alg_syscall": {"status": "accessible"},
            "functional_test": {"status": "no_modification", "detail": "primitive ran"},
            "modules_loaded": [],
            "modprobe_mitigation": {"present": False, "files": [], "completeness": "none", "warnings": []},
            "kernel_patch": {"detected": False, "evidence": None, "weak_evidence": None},
        }
        status, vulnerable, code, summary, _ = detector.verdict(host, checks)
        self.assertEqual(code, cfc.EXIT_UNVERIFIED)
        self.assertEqual(status, "unverified")
        self.assertFalse(vulnerable)
        self.assertIn("unverified", summary.lower())
        self.assertNotIn("non vulnerable", summary.lower())

    def test_verdict_no_modification_with_changelog_evidence_is_patched(self):
        detector = cfc.CopyFailDetector(functional_test=False)
        host = {"kernel": {"patch_status": "patched"}}
        checks = {
            "af_alg_syscall": {"status": "accessible"},
            "functional_test": {"status": "no_modification", "detail": "primitive ran"},
            "modules_loaded": [],
            "modprobe_mitigation": {"present": False, "files": [], "completeness": "none", "warnings": []},
            "kernel_patch": {"detected": True,
                             "evidence": "package changelog references CVE-2026-31431",
                             "weak_evidence": None},
        }
        status, vulnerable, code, _, _ = detector.verdict(host, checks)
        self.assertEqual(code, cfc.EXIT_SAFE)
        self.assertEqual(status, "patched")
        self.assertFalse(vulnerable)

    def test_verdict_setup_failed_is_unverified(self):
        detector = cfc.CopyFailDetector(functional_test=False)
        host = {"kernel": {"patch_status": "unverified"}}
        checks = {
            "af_alg_syscall": {"status": "accessible"},
            "functional_test": {"status": "setup_failed", "detail": "ALG_SET_KEY EINVAL"},
            "modules_loaded": [],
            "modprobe_mitigation": {"present": False, "files": [], "completeness": "none", "warnings": []},
            "kernel_patch": {"detected": False, "evidence": None, "weak_evidence": None},
        }
        _, _, code, _, _ = detector.verdict(host, checks)
        self.assertEqual(code, cfc.EXIT_UNVERIFIED)

    def test_blocked_af_alg_emits_mitigated(self):
        detector = cfc.CopyFailDetector(functional_test=False)
        host = {"kernel": {"patch_status": "unverified"}}
        checks = {
            "af_alg_syscall": {"status": "blocked"},
            "functional_test": {"status": "not_run"},
            "modules_loaded": [],
            "modprobe_mitigation": {"present": False, "files": [], "completeness": "none", "warnings": []},
            "kernel_patch": {"detected": False, "evidence": None, "weak_evidence": None},
        }
        _, _, code, _, _ = detector.verdict(host, checks)
        self.assertEqual(code, cfc.EXIT_MITIGATED)

    def test_removed_unsafe_heuristic_symbols_are_gone(self):
        self.assertFalse(hasattr(cfc, "LAST_UNFIXED_MAINLINE"))
        self.assertFalse(hasattr(cfc, "kernel_tuple"))

    def test_analyze_kernel_patch_never_detects_from_release_string_alone(self):
        """No matter how high the kernel version, absence of authoritative
        changelog evidence MUST yield detected=False. Guards against a
        renamed reimplementation of the LAST_UNFIXED_MAINLINE shortcut."""
        detector = cfc.CopyFailDetector(functional_test=False)
        with mock.patch.object(detector, "query_package_changelog", return_value=None):
            for release in ("7.0.0", "8.0.0", "9.99.99", "6.19.12-200.fc43.x86_64"):
                with self.subTest(release=release):
                    result = detector.analyze_kernel_patch(
                        {"ID": "fedora", "VERSION_ID": "43", "ID_LIKE": "rhel"},
                        release,
                        "Linux version {} test\n".format(release),
                    )
                    self.assertFalse(result["detected"],
                                     "release {} alone must not yield detected=True".format(release))
                    self.assertIsNone(result["evidence"])

    def test_query_package_changelog_uses_kernel_core_on_fedora(self):
        captured = []

        def fake_run(command, **kwargs):
            captured.append(command)
            class R:
                stdout = ""
                stderr = ""
            return R()

        detector = cfc.CopyFailDetector(functional_test=False)
        with mock.patch.object(cfc.shutil, "which", return_value="/usr/bin/rpm"), \
                mock.patch.object(cfc.subprocess, "run", side_effect=fake_run):
            detector.query_package_changelog(
                {"ID": "fedora", "VERSION_ID": "43", "ID_LIKE": "rhel"},
                "6.19.12-200.fc43.x86_64",
            )
        rpm_targets = [cmd[-1] for cmd in captured]
        self.assertTrue(any(t.startswith("kernel-core-") for t in rpm_targets),
                        "expected kernel-core-<release> probe, got {}".format(rpm_targets))
        self.assertTrue(rpm_targets[0].startswith("kernel-core-"),
                        "kernel-core probe must come first, got {}".format(rpm_targets))
        # release must be embedded so we never surface a different package's changelog
        self.assertIn("6.19.12-200.fc43.x86_64", rpm_targets[0])

    def test_json_and_sarif_are_parseable(self):
        result = {
            "tool": cfc.TOOL_NAME,
            "version": cfc.VERSION,
            "timestamp": cfc.utc_now_z(),
            "host": {"hostname": "test", "os": {}, "kernel": {"version": "6.6", "patch_status": "unverified"}},
            "checks": {
                "modprobe_mitigation": {"warnings": []},
            },
            "verdict": {
                "status": "unverified",
                "vulnerable": False,
                "exit_code": cfc.EXIT_UNVERIFIED,
                "summary": "test",
                "recommendations": [],
            },
        }
        import json
        self.assertEqual(json.loads(cfc.make_json(result))["tool"], cfc.TOOL_NAME)
        sarif = json.loads(cfc.make_sarif(result))
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(sarif["runs"][0]["tool"]["driver"]["rules"][0]["id"], cfc.RULE_ID)


if __name__ == "__main__":
    unittest.main()
