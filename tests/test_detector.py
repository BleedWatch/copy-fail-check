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
        detector.attempt_copy_fail_primitive = mock.Mock(side_effect=OSError(errno.EPERM, "blocked"))
        result = detector.run_functional_test()
        self.assertEqual(result["status"], "setup_failed")
        self.assertFalse(os.path.exists(sentinel))

    def test_verdict_exit_codes(self):
        detector = cfc.CopyFailDetector(functional_test=False)
        host = {"kernel": {"patch_status": "unverified"}}
        base_checks = {
            "af_alg_syscall": {"status": "accessible"},
            "functional_test": {"status": "not_run"},
            "modules_loaded": [],
            "modprobe_mitigation": {"present": False, "files": [], "completeness": "none", "warnings": []},
            "kernel_patch": {"detected": False, "evidence": None},
        }
        self.assertEqual(detector.verdict(host, base_checks)[2], cfc.EXIT_VULNERABLE)
        patched = dict(base_checks)
        patched["kernel_patch"] = {"detected": True, "evidence": "commit"}
        self.assertEqual(detector.verdict(host, patched)[2], cfc.EXIT_SAFE)
        mitigated = dict(base_checks)
        mitigated["modprobe_mitigation"] = {"present": True, "files": [], "completeness": "full", "warnings": []}
        self.assertEqual(detector.verdict(host, mitigated)[2], cfc.EXIT_MITIGATED)
        confirmed = dict(base_checks)
        confirmed["functional_test"] = {"status": "modification_detected"}
        self.assertEqual(detector.verdict(host, confirmed)[2], cfc.EXIT_VULNERABLE)

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
                "status": "vulnerable_inferred_kernel",
                "vulnerable": True,
                "exit_code": cfc.EXIT_VULNERABLE,
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
