"""
Manual integration test for the real Copy Fail primitive.

This test executes the actual AF_ALG sendmsg + splice + recv chain against
a /tmp sentinel and asserts the verdict matches the operator's expectation
for the running kernel. It is NOT part of the standard CI suite because:

  1. GitHub-hosted runners ship patched kernels — the test would always
     return no_modification there, which is fine, but provides no signal.
  2. Some kernels require CAP_NET_ADMIN to bind AF_ALG; non-root runs
     return setup_failed, which is also expected behavior, not a defect.

To run it manually on a host you control:

    sudo COPY_FAIL_EXPECT=vulnerable    python3 -m unittest tests.test_functional_real
    sudo COPY_FAIL_EXPECT=patched       python3 -m unittest tests.test_functional_real
    sudo COPY_FAIL_EXPECT=unverified    python3 -m unittest tests.test_functional_real

The test will skip if AF_ALG is not accessible.
"""
import errno
import importlib.util
import os
import socket
import unittest


ROOT = os.path.dirname(os.path.dirname(__file__))
SPEC = importlib.util.spec_from_file_location("copy_fail_check", os.path.join(ROOT, "copy-fail-check.py"))
cfc = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cfc)


class FunctionalRealTests(unittest.TestCase):
    def setUp(self):
        if not hasattr(socket, "AF_ALG"):
            self.skipTest("Python build has no socket.AF_ALG support")
        try:
            sock = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
        except OSError as exc:
            if exc.errno in (errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT):
                self.skipTest("AF_ALG syscall blocked in this environment")
            raise
        finally:
            try:
                sock.close()
            except (OSError, NameError):
                pass

    def test_real_primitive_against_kernel(self):
        expected = os.environ.get("COPY_FAIL_EXPECT")
        if expected is None:
            self.skipTest("Set COPY_FAIL_EXPECT=vulnerable|patched|unverified to run this manual test")

        detector = cfc.CopyFailDetector(functional_test=True)
        result = detector.run_functional_test()

        self.assertIn(result["status"], (
            "modification_detected", "no_modification", "setup_failed", "error",
        ))

        if expected == "vulnerable":
            self.assertEqual(result["status"], "modification_detected",
                             msg="Expected vulnerable kernel but got: {}".format(result))
        elif expected == "patched":
            self.assertEqual(result["status"], "no_modification",
                             msg="Expected patched kernel but got: {}".format(result))
        elif expected == "unverified":
            self.assertIn(result["status"], ("setup_failed", "error"),
                          msg="Expected unverified but got: {}".format(result))
        else:
            self.fail("Unknown COPY_FAIL_EXPECT value: {}".format(expected))


if __name__ == "__main__":
    unittest.main()
