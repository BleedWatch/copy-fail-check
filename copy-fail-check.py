#!/usr/bin/env python3
"""
copy-fail-check - Detection and remediation toolkit for CVE-2026-31431.
Maintained by BleedWatch SASU. https://github.com/bleedwatch/copy-fail-check
"""

import argparse
import atexit
import ctypes
import ctypes.util
import errno
import glob
import hashlib
import json
import os
import platform
import secrets
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
from datetime import datetime, timezone


VERSION = "1.1.1"
TOOL_NAME = "copy-fail-check"
REPOSITORY_URL = "https://github.com/bleedwatch/copy-fail-check"
INFO_URI = REPOSITORY_URL
CVE_ID = "CVE-2026-31431"
RULE_ID = "BLEEDWATCH-CVE-2026-31431"
AUDIT_LOG = "/var/log/bleedwatch-copy-fail-mitigation.log"
MITIGATION_FILE = "/etc/modprobe.d/disable-af-alg.conf"
MODULES = ("af_alg", "algif_aead", "algif_skcipher", "algif_hash", "algif_rng")
ALGIF_MODULES = ("algif_aead", "algif_skcipher", "algif_hash", "algif_rng")
PATCH_COMMIT = "a664bf3d603d"

# AF_ALG socket-option constants (uapi/linux/if_alg.h)
SOL_ALG = 279
ALG_SET_KEY = 1
ALG_SET_IV = 2
ALG_SET_OP = 3
ALG_SET_AEAD_ASSOCLEN = 4
ALG_OP_DECRYPT = 0
# crypto_authenc rtattr key wrapper (crypto/authenc.c)
CRYPTO_AUTHENC_KEYA_PARAM = 1

EXIT_SAFE = 0
EXIT_VULNERABLE = 2
EXIT_MITIGATED = 3
EXIT_DETECTION_ERROR = 10
EXIT_UNVERIFIED = 11
EXIT_RUNTIME_ERROR = 11  # intentional alias of EXIT_UNVERIFIED: both mean "non-conclusive, re-investigate"
EXIT_REMEDIATED = 20
EXIT_REMEDIATION_CANCELLED = 21
EXIT_REMEDIATION_FAILED = 22


def utc_now_z():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_text(path, default=""):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return default


def write_all(fd, data):
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        view = view[written:]


_LIBC_SPLICE = None


def _libc_splice():
    global _LIBC_SPLICE
    if _LIBC_SPLICE is not None:
        return _LIBC_SPLICE
    libc_name = ctypes.util.find_library("c") or "libc.so.6"
    libc = ctypes.CDLL(libc_name, use_errno=True)
    fn = libc.splice
    fn.restype = ctypes.c_ssize_t
    fn.argtypes = (ctypes.c_int, ctypes.c_void_p,
                   ctypes.c_int, ctypes.c_void_p,
                   ctypes.c_size_t, ctypes.c_uint)
    _LIBC_SPLICE = fn
    return fn


def splice_compat(in_fd, out_fd, length):
    if hasattr(os, "splice"):
        return os.splice(in_fd, out_fd, length)
    fn = _libc_splice()
    n = fn(in_fd, None, out_fd, None, length, 0)
    if n < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return n


def parse_os_release_content(content):
    result = {}
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] == '"':
            value = value[1:-1]
        result[key] = value
    return result


def module_name_from_proc(name):
    return name.replace("-", "_")


def distro_family(os_info):
    distro_id = os_info.get("ID", "").lower()
    like = os_info.get("ID_LIKE", "").lower().split()
    names = [distro_id] + like
    if any(name in names for name in ("debian", "ubuntu")):
        return "debian"
    if any(name in names for name in ("rhel", "fedora", "centos", "amzn", "amazon")):
        return "rhel"
    if any(name in names for name in ("suse", "opensuse", "sles")):
        return "suse"
    return "unsupported"


def colorize(text, color, enabled):
    if not enabled:
        return text
    colors = {"red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m", "bold": "\033[1m"}
    return colors.get(color, "") + text + "\033[0m"


class CopyFailDetector:
    def __init__(self, root="/", tmp_dir="/tmp", functional_test=True):
        self.root = root
        self.tmp_dir = tmp_dir
        self.functional_test = functional_test
        self.warnings = []

    def root_path(self, absolute_path):
        if self.root == "/":
            return absolute_path
        return os.path.join(self.root, absolute_path.lstrip("/"))

    def detect(self):
        timestamp = utc_now_z()
        host = {
            "hostname": platform.node(),
            "os": {"distro": None, "version": None, "codename": None, "family": None},
            "kernel": {"version": platform.release(), "patch_status": "unverified"},
        }
        checks = {
            "environment": {"status": "unknown", "errors": []},
            "af_alg_syscall": {"status": "unknown", "errno": None, "detail": None},
            "functional_test": {"status": "not_run", "detail": None},
            "modules_loaded": [],
            "module_provenance": {"af_alg": "unknown", "algif_aead": "unknown",
                                  "algif_skcipher": "unknown", "algif_hash": "unknown",
                                  "algif_rng": "unknown", "any_builtin": False},
            "modprobe_mitigation": {"present": False, "files": [], "completeness": "none", "warnings": []},
            "kernel_boot_mitigation": {"initcall_blacklist": [], "blocks_copy_fail": False,
                                       "source": None, "warnings": []},
            "kernel_patch": {"detected": False, "evidence": None, "weak_evidence": None},
        }

        env_status, env_errors, os_info = self.detect_environment()
        checks["environment"] = {"status": env_status, "errors": env_errors}
        host["os"] = {
            "distro": os_info.get("ID"),
            "version": os_info.get("VERSION_ID"),
            "codename": os_info.get("VERSION_CODENAME") or os_info.get("UBUNTU_CODENAME"),
            "family": distro_family(os_info),
        }

        release = platform.release()
        proc_version = read_text(self.root_path("/proc/version"), default="")
        host["kernel"]["version"] = release

        modules_loaded = self.list_loaded_modules()
        checks["modules_loaded"] = modules_loaded
        checks["module_provenance"] = self.analyze_module_provenance(release)
        checks["modprobe_mitigation"] = self.analyze_modprobe()
        checks["kernel_boot_mitigation"] = self.analyze_kernel_boot_mitigation(release)
        checks["kernel_patch"] = self.analyze_kernel_patch(os_info, release, proc_version)
        host["kernel"]["patch_status"] = "patched" if checks["kernel_patch"]["detected"] else "unverified"

        if env_status != "ok":
            return self.build_result(timestamp, host, checks, "detection_error", True, EXIT_RUNTIME_ERROR,
                                     "Unsupported or unexpected runtime environment", env_errors)

        checks["af_alg_syscall"] = self.check_af_alg_syscall()
        af_status = checks["af_alg_syscall"]["status"]
        if af_status == "accessible" and self.functional_test:
            checks["functional_test"] = self.run_functional_test()
        elif af_status == "blocked":
            checks["functional_test"] = {"status": "not_run", "detail": "AF_ALG unavailable"}
        else:
            checks["functional_test"] = {"status": "not_run", "detail": "AF_ALG status did not permit safe test"}

        verdict_status, vulnerable, exit_code, summary, recommendations = self.verdict(host, checks)
        return self.build_result(timestamp, host, checks, verdict_status, vulnerable, exit_code, summary,
                                 recommendations)

    def build_result(self, timestamp, host, checks, verdict_status, vulnerable, exit_code, summary, recommendations):
        return {
            "tool": TOOL_NAME,
            "version": VERSION,
            "timestamp": timestamp,
            "host": host,
            "checks": checks,
            "verdict": {
                "status": verdict_status,
                "vulnerable": vulnerable,
                "exit_code": exit_code,
                "summary": summary,
                "recommendations": recommendations,
            },
        }

    def detect_environment(self):
        errors = []
        if sys.platform != "linux":
            errors.append("copy-fail-check supports Linux only")
        if "microsoft" in platform.release().lower() and not os.path.exists("/proc/sys/kernel/osrelease"):
            errors.append("WSL1 is not supported")
        proc_path = self.root_path("/proc/version")
        if not os.path.exists(proc_path):
            errors.append("/proc is not accessible")
        os_release = self.root_path("/etc/os-release")
        os_info = parse_os_release_content(read_text(os_release, default=""))
        if not os_info:
            errors.append("/etc/os-release is missing or unreadable")
        elif distro_family(os_info) == "unsupported":
            errors.append("unsupported Linux distribution: {}".format(os_info.get("ID", "unknown")))
        return ("error" if errors else "ok", errors, os_info)

    def check_af_alg_syscall(self):
        if not hasattr(socket, "AF_ALG"):
            return {"status": "blocked", "errno": errno.EAFNOSUPPORT, "detail": "Python socket has no AF_ALG support"}
        sock = None
        try:
            sock = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
            return {"status": "accessible", "errno": None, "detail": "AF_ALG socket creation succeeded"}
        except OSError as exc:
            if exc.errno in (errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT):
                return {"status": "blocked", "errno": exc.errno, "detail": os.strerror(exc.errno)}
            return {"status": "error", "errno": exc.errno, "detail": str(exc)}
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    def list_loaded_modules(self):
        content = read_text(self.root_path("/proc/modules"), default="")
        loaded = []
        wanted = set(MODULES)
        for line in content.splitlines():
            fields = line.split()
            if fields:
                module = module_name_from_proc(fields[0])
                if module in wanted:
                    loaded.append(module)
        return loaded

    def analyze_modprobe(self):
        files = []
        blocked = {}
        warnings = []
        pattern = self.root_path("/etc/modprobe.d/*.conf")
        for path in sorted(glob.glob(pattern)):
            content = read_text(path, default="")
            seen = []
            for line in content.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                tokens = stripped.split()
                if len(tokens) >= 2 and tokens[0] == "blacklist":
                    module = module_name_from_proc(tokens[1])
                    if module in MODULES:
                        blocked[module] = "blacklist"
                        seen.append(module)
                if len(tokens) >= 3 and tokens[0] == "install":
                    module = module_name_from_proc(tokens[1])
                    command = " ".join(tokens[2:])
                    if module in MODULES and command in ("/bin/false", "/usr/bin/false", "false", "/bin/true"):
                        blocked[module] = "install"
                        seen.append(module)
            if seen:
                files.append(path if self.root == "/" else "/" + os.path.relpath(path, self.root))
        if "af_alg" in blocked and "algif_aead" not in blocked:
            warnings.append("af_alg is blocked but algif_aead is not explicitly blocked")
        missing = [module for module in MODULES if module not in blocked]
        if not blocked:
            completeness = "none"
        elif missing:
            completeness = "partial"
        else:
            completeness = "full"
        return {"present": bool(blocked), "files": files, "completeness": completeness, "warnings": warnings}

    def analyze_module_provenance(self, release):
        """Determine for each AF_ALG-related module whether it is built into
        the kernel image (CONFIG=y) or loadable (CONFIG=m). Built-in modules
        cannot be blocked by /etc/modprobe.d/* — modprobe is consulted only
        for loadable modules. RHEL 8/9/10 ships af_alg and algif_aead as
        built-in, so the v1.0.0/v1.1.0 modprobe-based remediation is inert
        on those distros and a different mitigation path is required.

        Sources, in order of authority:
          1. /lib/modules/<release>/modules.builtin (kmod's authoritative
             list of compiled-in modules, generated from kbuild).
          2. /sys/module/<name> existence (the module is present in the
             kernel, but this does not distinguish builtin from loaded).
        """
        result = {"af_alg": "unknown", "algif_aead": "unknown",
                  "algif_skcipher": "unknown", "algif_hash": "unknown",
                  "algif_rng": "unknown", "any_builtin": False, "source": None}

        builtin_path = self.root_path("/lib/modules/{}/modules.builtin".format(release))
        builtin_content = read_text(builtin_path, default="")
        if builtin_content:
            result["source"] = builtin_path
            builtin_set = set()
            for line in builtin_content.splitlines():
                stripped = line.strip()
                if not stripped:
                    continue
                base = os.path.basename(stripped)
                if base.endswith(".ko"):
                    base = base[:-3]
                builtin_set.add(module_name_from_proc(base))
            for module in MODULES:
                if module in builtin_set:
                    result[module] = "builtin"

        loaded = set(self.list_loaded_modules())
        for module in MODULES:
            if result[module] != "builtin":
                if module in loaded:
                    result[module] = "loaded_module"
                else:
                    sys_path = self.root_path("/sys/module/{}".format(module))
                    if os.path.isdir(sys_path):
                        sections = self.root_path("/sys/module/{}/sections".format(module))
                        if not os.path.isdir(sections):
                            result[module] = "builtin"
                        else:
                            result[module] = "loadable"
                    elif builtin_content:
                        result[module] = "loadable"

        result["any_builtin"] = any(result[m] == "builtin" for m in MODULES)
        return result

    def analyze_kernel_boot_mitigation(self, release):
        """Detect whether the running kernel was booted with one of the
        Red Hat-recommended initcall_blacklist boot arguments that disable
        the affected init paths. This is the only modprobe-equivalent
        mitigation for distros where algif_aead is compiled in.

        Recognized blacklist tokens (per access.redhat.com/security/cve/cve-2026-31431):
          - algif_aead_init                 (specific affected module)
          - af_alg_init                     (entire AF_ALG family)
          - crypto_authenc_esn_module_init  (only the affected algorithm)
        """
        cmdline = read_text(self.root_path("/proc/cmdline"), default="").strip()
        result = {"initcall_blacklist": [], "blocks_copy_fail": False,
                  "source": "/proc/cmdline" if cmdline else None, "warnings": []}
        if not cmdline:
            return result
        relevant = ("algif_aead_init", "af_alg_init", "crypto_authenc_esn_module_init")
        found = []
        for token in cmdline.split():
            if not token.startswith("initcall_blacklist="):
                continue
            entries = token.split("=", 1)[1].split(",")
            for entry in entries:
                if entry in relevant:
                    found.append(entry)
        result["initcall_blacklist"] = found
        result["blocks_copy_fail"] = bool(found)
        return result

    def analyze_kernel_patch(self, os_info, release, proc_version):
        evidence = self.query_package_changelog(os_info, release)
        if evidence:
            return {"detected": True, "evidence": evidence, "weak_evidence": None}
        weak = None
        weak_tokens = (CVE_ID, PATCH_COMMIT, "authencesn", "copy fail")
        haystack = "\n".join([proc_version, release]).lower()
        for token in weak_tokens:
            if token.lower() in haystack:
                weak = "kernel build metadata references {}".format(token)
                break
        return {"detected": False, "evidence": None, "weak_evidence": weak}

    def query_package_changelog(self, os_info, release):
        family = distro_family(os_info)
        commands = []
        # Each query is pinned to the running kernel release so we never
        # surface the changelog of a freshly-installed-but-not-yet-booted
        # patched package while the host is still running an older
        # vulnerable kernel.
        if family == "debian" and shutil.which("apt"):
            commands.append(["apt", "changelog", "linux-image-{}".format(release)])
        elif family == "rhel" and shutil.which("rpm"):
            if os_info.get("ID", "").lower() == "fedora":
                commands.append(["rpm", "-q", "--changelog", "kernel-core-{}".format(release)])
            commands.append(["rpm", "-q", "--changelog", "kernel-{}".format(release)])
        elif family == "suse" and shutil.which("rpm"):
            commands.append(["rpm", "-q", "--changelog", "kernel-default-{}".format(release)])
            commands.append(["rpm", "-q", "--changelog", "kernel-{}".format(release)])
        for command in commands:
            try:
                completed = subprocess.run(command, check=False, timeout=60, capture_output=True, text=True)
            except (OSError, subprocess.SubprocessError):
                continue
            haystack = (completed.stdout + "\n" + completed.stderr).lower()
            for token in (CVE_ID.lower(), PATCH_COMMIT.lower(), "authencesn", "copy fail"):
                if token in haystack:
                    return "package changelog references {}".format(token)
        return None

    def make_sentinel_path(self):
        token = secrets.token_hex(8)
        return os.path.join(self.tmp_dir, "copy-fail-sentinel-{}-{}-{}".format(os.getpid(), time.time_ns(), token))

    def run_functional_test(self):
        path = self.make_sentinel_path()
        if not path.startswith(self.tmp_dir.rstrip("/") + "/"):
            return {"status": "setup_failed", "detail": "sentinel path outside configured tmp_dir"}
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        state = {"fd": None}
        cleanup_done = {"ok": False}
        previous_handlers = {}

        def cleanup():
            if state["fd"] is not None:
                try:
                    os.close(state["fd"])
                except OSError:
                    pass
                state["fd"] = None
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass
            except OSError:
                pass
            cleanup_done["ok"] = not os.path.exists(path)

        def signal_handler(signum, frame):
            cleanup()
            if not cleanup_done["ok"]:
                raise RuntimeError("sentinel cleanup failed after signal {}".format(signum))
            previous = previous_handlers.get(signum)
            if callable(previous):
                signal.signal(signum, previous)
                previous(signum, frame)
            if signum == signal.SIGINT:
                raise KeyboardInterrupt
            raise SystemExit(128 + signum)

        try:
            if os.path.exists(path):
                return {"status": "setup_failed", "detail": "sentinel path collision refused"}
            state["fd"] = os.open(path, flags, 0o600)
            mode = stat.S_IMODE(os.fstat(state["fd"]).st_mode)
            if mode != 0o600:
                return {"status": "setup_failed", "detail": "sentinel permissions were not 0600"}
            atexit.register(cleanup)
            for signum in (signal.SIGINT, signal.SIGTERM):
                previous_handlers[signum] = signal.getsignal(signum)
                signal.signal(signum, signal_handler)

            pattern = (b"CFCHECK:" * 512)[:4096]
            write_all(state["fd"], pattern)
            os.fsync(state["fd"])
            os.lseek(state["fd"], 0, os.SEEK_SET)
            os.read(state["fd"], len(pattern))
            primitive = self.execute_copy_fail_primitive(state["fd"], path)
            os.lseek(state["fd"], 0, os.SEEK_SET)
            after = os.read(state["fd"], len(pattern))
            if after != pattern:
                diffs = [(i, pattern[i], after[i]) for i in range(len(pattern)) if pattern[i] != after[i]]
                first_offset = diffs[0][0] if diffs else 0
                detail = ("sentinel page cache modified by Copy Fail primitive "
                          "at offset {} ({} byte(s) altered)").format(first_offset, len(diffs))
                if primitive["status"] == "attempted":
                    detail += "; full sendmsg+splice+recv chain executed"
                return {"status": "modification_detected", "detail": detail}
            if primitive["status"] == "attempted":
                return {"status": "no_modification",
                        "detail": "primitive ran end-to-end and sentinel remained unchanged"}
            return {"status": primitive["status"], "detail": primitive.get("detail")}
        except OSError as exc:
            detail = "{}: {}".format(exc.errno, exc.strerror)
            if exc.errno in (errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT, errno.EPERM, errno.EACCES):
                return {"status": "setup_failed", "detail": detail}
            return {"status": "error", "detail": detail}
        finally:
            cleanup()
            try:
                atexit.unregister(cleanup)
            except (AttributeError, ValueError):
                pass
            for signum, previous in previous_handlers.items():
                try:
                    signal.signal(signum, previous)
                except (OSError, RuntimeError, ValueError):
                    pass

    def execute_copy_fail_primitive(self, sentinel_fd, sentinel_path):
        """Run the Copy Fail primitive non-destructively on a /tmp sentinel.

        Sets up an AF_ALG aead authencesn(hmac(sha1),cbc(aes)) socket, then
        sendmsg(MSG_MORE) with controlled AAD, splice(sentinel -> pipe -> op
        socket), and recv() to drive the in-place AEAD decrypt that triggers
        the buggy scratch write into the spliced page cache pages on
        vulnerable kernels.

        We deliberately do NOT call posix_fadvise(POSIX_FADV_DONTNEED) on
        the sentinel: that would evict the modified page cache and erase
        the very marker we are trying to detect.

        Touches no file outside the supplied sentinel_fd / sentinel_path.

        Returns dict {"status": ..., "detail": ...} with status:
          - "attempted":      full sendmsg+splice+recv chain ran end-to-end
          - "setup_failed":   AF_ALG/key/accept/sendmsg/splice setup failed
          - "error":          unexpected failure
        """
        expected_prefix = self.tmp_dir.rstrip("/") + "/"
        if not sentinel_path.startswith(expected_prefix):
            return {"status": "setup_failed",
                    "detail": "refusing to operate outside tmp_dir ({})".format(self.tmp_dir)}
        if not hasattr(socket, "AF_ALG"):
            return {"status": "setup_failed",
                    "detail": "Python build has no socket.AF_ALG"}

        base = None
        op = None
        pipe_r = -1
        pipe_w = -1
        try:
            try:
                base = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
            except OSError as exc:
                return {"status": "setup_failed",
                        "detail": "AF_ALG socket creation failed: {}".format(exc)}

            try:
                base.bind(("aead", "authencesn(hmac(sha1),cbc(aes))"))
            except OSError as exc:
                return {"status": "setup_failed",
                        "detail": "bind authencesn unavailable: {}".format(exc)}

            # authenc key layout (crypto/authenc.c::crypto_authenc_extractkeys):
            # rtattr {len=8 (host endian), type=CRYPTO_AUTHENC_KEYA_PARAM},
            # crypto_authenc_key_param.enckeylen=16 (BIG endian, be32_to_cpu),
            # then auth_key (8 bytes HMAC) || enc_key (16 bytes AES-128).
            rtattr = struct.pack("=HH", 8, CRYPTO_AUTHENC_KEYA_PARAM) + struct.pack(">I", 16)
            key_buf = rtattr + (b"\x00" * 24)
            try:
                base.setsockopt(SOL_ALG, ALG_SET_KEY, key_buf)
            except OSError as exc:
                return {"status": "setup_failed",
                        "detail": "ALG_SET_KEY failed: {}".format(exc)}

            try:
                op, _ = base.accept()
            except OSError as exc:
                return {"status": "setup_failed",
                        "detail": "AF_ALG accept failed: {}".format(exc)}

            try:
                pipe_r, pipe_w = os.pipe()
            except OSError as exc:
                return {"status": "setup_failed",
                        "detail": "pipe creation failed: {}".format(exc)}

            iv = b"\x00" * 16
            marker = b"PWND" + b"\x00" * 4  # 8-byte AAD
            cmsg = [
                (SOL_ALG, ALG_SET_OP, struct.pack("=I", ALG_OP_DECRYPT)),
                (SOL_ALG, ALG_SET_IV, struct.pack("=I", 16) + iv),
                (SOL_ALG, ALG_SET_AEAD_ASSOCLEN, struct.pack("=I", 8)),
            ]
            try:
                op.sendmsg([marker], cmsg, socket.MSG_MORE)
            except OSError as exc:
                return {"status": "setup_failed",
                        "detail": "AF_ALG sendmsg failed: {}".format(exc)}

            splice_len = 32
            os.lseek(sentinel_fd, 0, os.SEEK_SET)
            try:
                n = splice_compat(sentinel_fd, pipe_w, splice_len)
                if n <= 0:
                    return {"status": "setup_failed",
                            "detail": "splice(sentinel -> pipe) returned {}".format(n)}
                n = splice_compat(pipe_r, op.fileno(), splice_len)
                if n <= 0:
                    return {"status": "setup_failed",
                            "detail": "splice(pipe -> op) returned {}".format(n)}
            except OSError as exc:
                return {"status": "setup_failed",
                        "detail": "splice failed: {}".format(exc)}

            # recv drives the in-place AEAD decrypt; on vulnerable kernels
            # the buggy scratch copy lands BEFORE the auth check fails, so
            # EBADMSG / EINVAL here is expected and not a setup failure.
            try:
                op.recv(splice_len)
            except OSError as exc:
                if exc.errno not in (errno.EBADMSG, errno.EINVAL,
                                     errno.EAGAIN, errno.EMSGSIZE):
                    return {"status": "setup_failed",
                            "detail": "AF_ALG recv unexpected error: {}".format(exc)}

            return {"status": "attempted",
                    "detail": "AF_ALG sendmsg + splice + recv chain executed against sentinel"}
        except OSError as exc:
            return {"status": "error", "detail": "{}: {}".format(exc.errno, exc.strerror)}
        finally:
            if op is not None:
                try:
                    op.close()
                except OSError:
                    pass
            if base is not None:
                try:
                    base.close()
                except OSError:
                    pass
            for fd in (pipe_r, pipe_w):
                if fd != -1:
                    try:
                        os.close(fd)
                    except OSError:
                        pass

    def verdict(self, host, checks):
        mitigation = checks["modprobe_mitigation"]
        patch = checks["kernel_patch"]
        af_alg = checks["af_alg_syscall"]
        functional = checks["functional_test"]
        provenance = checks.get("module_provenance", {})
        boot_mit = checks.get("kernel_boot_mitigation", {})
        loaded = set(checks["modules_loaded"])
        recommendations = []

        any_builtin = bool(provenance.get("any_builtin"))
        boot_blocks = bool(boot_mit.get("blocks_copy_fail"))

        if any_builtin and not boot_blocks:
            builtin_modules = [m for m in MODULES if provenance.get(m) == "builtin"]
            recommendations.append(
                "Modules built into this kernel ({}); modprobe blacklist is INERT on this system. "
                "Reboot with one of: initcall_blacklist=algif_aead_init  /  "
                "initcall_blacklist=af_alg_init  /  initcall_blacklist=crypto_authenc_esn_module_init "
                "(see access.redhat.com/security/cve/cve-2026-31431). "
                "For a no-reboot alternative, deploy an eBPF LSM blocker on socket_create denying family=AF_ALG."
                .format(", ".join(builtin_modules))
            )
        if loaded and mitigation["present"]:
            recommendations.append("Reboot to unload AF_ALG modules that were already resident before mitigation")
        if mitigation["completeness"] == "partial":
            recommendations.append("Complete modprobe mitigation for af_alg and algif_* modules")

        if functional["status"] == "modification_detected":
            if any_builtin:
                recommendations.append(
                    "Apply the vendor kernel update; modprobe-based --remediate will NOT mitigate this host "
                    "(modules are built-in). Use initcall_blacklist boot args or eBPF LSM as interim mitigation."
                )
            else:
                recommendations.append("Apply the vendor kernel update or run --remediate for immediate AF_ALG mitigation")
            return ("vulnerable_confirmed_functional", True, EXIT_VULNERABLE,
                    "Vulnerable - functional sentinel test confirmed Copy Fail primitive landed marker in page cache",
                    recommendations)

        if boot_blocks:
            recommendations.append("Install the vendor kernel update when available; keep boot mitigation in place")
            return ("mitigated_initcall", False, EXIT_MITIGATED,
                    "Vulnerable kernel exposure mitigated - boot arg disables affected initcall: {}".format(
                        ", ".join(boot_mit.get("initcall_blacklist") or [])),
                    recommendations)

        if af_alg["status"] == "blocked" or (mitigation["completeness"] == "full" and not any_builtin):
            recommendations.append("Install the vendor kernel update when available; keep mitigation until reboot validation")
            return ("mitigated_modprobe", False, EXIT_MITIGATED,
                    "Vulnerable kernel exposure mitigated - AF_ALG blocked or fully disabled", recommendations)

        if af_alg["status"] not in ("accessible",):
            recommendations.append("Re-run on the host (not inside a restricted container) and with root privileges")
            return ("detection_error", True, EXIT_DETECTION_ERROR,
                    "Detection inconclusive - AF_ALG syscall check returned status '{}'".format(af_alg["status"]),
                    recommendations)

        if functional["status"] == "no_modification":
            if patch["detected"]:
                if mitigation["present"] and loaded:
                    recommendations.append("Reboot when practical so loaded AF_ALG modules match boot-time policy")
                return ("patched", False, EXIT_SAFE,
                        "Non vulnerable - kernel patch evidence found in changelog (authoritative) and functional test confirmed primitive blocked",
                        recommendations)
            recommendations.append("Verify the kernel against the vendor advisory before trusting this verdict")
            recommendations.append("Apply the vendor kernel update or run sudo python3 copy-fail-check.py --remediate")
            return ("unverified", False, EXIT_UNVERIFIED,
                    "Unverified - functional test reported no modification but no authoritative patch evidence was found; do not trust this as patched",
                    recommendations)

        if functional["status"] == "setup_failed":
            recommendations.append("Re-run as root; the functional Copy Fail primitive could not be set up in this environment")
            recommendations.append("If kernel changelog evidence is present, treat as likely patched; otherwise treat as unverified")
            detail = functional.get("detail") or "unknown"
            return ("unverified", False, EXIT_UNVERIFIED,
                    "Unverified - functional test setup failed ({}); cannot confirm or deny exposure".format(detail),
                    recommendations)

        if functional["status"] == "not_run" and patch["detected"]:
            return ("patched", False, EXIT_SAFE,
                    "Non vulnerable - kernel patch evidence found in changelog (authoritative)", recommendations)

        if functional["status"] == "not_run":
            recommendations.append("Re-run without --verify to execute the functional Copy Fail primitive test")
            return ("unverified", False, EXIT_UNVERIFIED,
                    "Unverified - functional test was not executed and no authoritative patch evidence was found",
                    recommendations)

        recommendations.append("Re-run on the host (not inside a restricted container) and with root privileges")
        return ("detection_error", True, EXIT_DETECTION_ERROR,
                "Detection inconclusive - AF_ALG syscall check failed unexpectedly", recommendations)


class CopyFailRemediator:
    def __init__(self, root="/", input_func=input, subprocess_run=subprocess.run, euid_func=None):
        self.root = root
        self.input_func = input_func
        self.subprocess_run = subprocess_run
        self.euid_func = euid_func or (os.geteuid if hasattr(os, "geteuid") else lambda: 1)
        self.actions = []
        self.warnings = []

    def root_path(self, absolute_path):
        if self.root == "/":
            return absolute_path
        return os.path.join(self.root, absolute_path.lstrip("/"))

    def desired_content(self):
        return "\n".join([
            "# CVE-2026-31431 (Copy Fail) mitigation",
            "# Generated by copy-fail-check v{} on {}".format(VERSION, utc_now_z().split("T")[0]),
            "# {}".format(REPOSITORY_URL),
            "# Audit log: {}".format(AUDIT_LOG),
            "install af_alg          /bin/false",
            "install algif_aead      /bin/false",
            "install algif_skcipher  /bin/false",
            "install algif_hash      /bin/false",
            "install algif_rng       /bin/false",
            "",
        ])

    def confirm(self):
        if os.environ.get("BLEEDWATCH_AUTO_CONFIRM") == "1":
            return True
        print("copy-fail-check remediation will:")
        print("  - create or update {}".format(MITIGATION_FILE))
        print("  - unload AF_ALG modules when possible")
        print("  - rebuild initramfs using the detected distribution tool")
        print("  - append audit details to {}".format(AUDIT_LOG))
        answer = self.input_func("Type 'CONFIRM' to proceed: ")
        return answer == "CONFIRM"

    def remediate(self):
        if self.euid_func() != 0:
            return EXIT_REMEDIATION_FAILED, "Root privileges are required for remediation"
        modprobe_dir = self.root_path("/etc/modprobe.d")
        if not os.path.isdir(modprobe_dir) or not os.access(modprobe_dir, os.W_OK):
            return EXIT_REMEDIATION_FAILED, "{} is not writable".format(modprobe_dir)

        preflight_detector = CopyFailDetector(root=self.root, functional_test=False)
        provenance = preflight_detector.analyze_module_provenance(platform.release())
        builtin_modules = [m for m in MODULES if provenance.get(m) == "builtin"]
        if builtin_modules:
            self.warnings.append(
                "Built-in modules detected: {}. Modprobe-based remediation is INERT on this kernel "
                "and will not block AF_ALG. Refusing to write a misleading mitigation file. "
                "Use one of the following alternatives:".format(", ".join(builtin_modules))
            )
            self.warnings.append(
                "Boot args (reboot required, RHEL official): add to GRUB_CMDLINE_LINUX one of "
                "'initcall_blacklist=algif_aead_init', 'initcall_blacklist=af_alg_init', or "
                "'initcall_blacklist=crypto_authenc_esn_module_init', then run 'grub2-mkconfig -o "
                "/boot/grub2/grub.cfg' (or update-grub on Debian-family) and reboot. See "
                "access.redhat.com/security/cve/cve-2026-31431."
            )
            self.warnings.append(
                "No-reboot eBPF LSM workaround (requires CONFIG_BPF_LSM=y and 'bpf' in "
                "/sys/kernel/security/lsm): deploy a socket_create LSM hook that returns -EPERM for "
                "family=AF_ALG. Reference implementation: github.com/lestercheung/linux-copy-fail-workarounds "
                "(NOTE: at audit time, that block_af_alg.c lacks the trailing 'int ret' hook arg and "
                "prior-return preservation, which can interfere with other BPF LSM programs in the chain — "
                "review and patch the LSM signature before production deployment, and persist the link via "
                "systemd or BPF pinning so the mitigation survives loader exit)."
            )
            return EXIT_REMEDIATION_FAILED, (
                "Refusing modprobe remediation: af_alg/algif_aead are built into this kernel. "
                "See warnings for the boot-arg and eBPF LSM alternatives."
            )

        if not self.confirm():
            return EXIT_REMEDIATION_CANCELLED, "Remediation cancelled by user"

        try:
            self.ensure_audit_log()
            self.backup_blacklist_conf()
            self.write_mitigation_file()
            self.unload_modules()
            self.rebuild_initramfs()
            detector = CopyFailDetector(root=self.root, functional_test=False)
            result = detector.detect()
            self.audit("post_check", json.dumps(result["verdict"], sort_keys=True))
            if result["verdict"]["exit_code"] in (EXIT_SAFE, EXIT_MITIGATED):
                return EXIT_REMEDIATED, "Remediation applied; reboot recommended"
            return EXIT_REMEDIATION_FAILED, "Post-check still reports exposure: {}".format(result["verdict"]["summary"])
        except OSError as exc:
            self.audit("error", str(exc))
            return EXIT_REMEDIATION_FAILED, str(exc)

    def ensure_audit_log(self):
        log_path = self.root_path(AUDIT_LOG)
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.fchmod(fd, 0o600)
            if self.euid_func() == 0:
                try:
                    os.fchown(fd, 0, 0)
                except OSError:
                    pass
        finally:
            os.close(fd)

    def audit(self, event, message):
        log_path = self.root_path(AUDIT_LOG)
        line = "{} {} {}\n".format(utc_now_z(), event, message.replace("\n", "\\n"))
        fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, line.encode("utf-8"))
        finally:
            os.close(fd)

    def backup_blacklist_conf(self):
        path = self.root_path("/etc/modprobe.d/blacklist.conf")
        if os.path.exists(path):
            backup = "{}.bak.{}".format(path, int(time.time()))
            shutil.copy2(path, backup)
            self.actions.append("backed up {}".format(backup))
            self.audit("backup", backup)

    def write_mitigation_file(self):
        path = self.root_path(MITIGATION_FILE)
        desired = self.desired_content()
        if os.path.exists(path):
            current = read_text(path, default="")
            if current == desired:
                self.actions.append("mitigation file already current")
                self.audit("skip", "{} already current".format(MITIGATION_FILE))
                return
            current_hash = hashlib.sha256(current.encode("utf-8", errors="replace")).hexdigest()
            backup = "{}.bak.{}".format(path, int(time.time()))
            shutil.copy2(path, backup)
            warning = "{} differed from desired content; backed up to {} sha256={}".format(
                MITIGATION_FILE, backup, current_hash
            )
            self.warnings.append(warning)
            self.audit("warning", warning)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(desired)
        os.chmod(path, 0o644)
        self.actions.append("wrote {}".format(MITIGATION_FILE))
        self.audit("write", MITIGATION_FILE)

    def unload_modules(self):
        for module in list(ALGIF_MODULES) + ["af_alg"]:
            command = ["rmmod", module]
            self.run_command(command, "rmmod {}".format(module))

    def rebuild_initramfs(self):
        os_info = parse_os_release_content(read_text(self.root_path("/etc/os-release"), default=""))
        family = distro_family(os_info)
        command = None
        if family == "debian":
            command = ["update-initramfs", "-u"]
        elif family == "rhel":
            command = ["dracut", "-f"]
        elif family == "suse":
            command = ["dracut", "-f"] if shutil.which("dracut") else ["mkinitrd"]
        if command is None:
            self.audit("skip", "unsupported initramfs family {}".format(family))
            return
        self.run_command(command, "initramfs rebuild")

    def run_command(self, command, label):
        try:
            completed = self.subprocess_run(
                command, check=False, timeout=60, capture_output=True, text=True, shell=False
            )
            stdout = completed.stdout or ""
            stderr = completed.stderr or ""
            self.audit("command", "{} rc={} stdout={} stderr={}".format(label, completed.returncode, stdout, stderr))
            self.actions.append("{} rc={}".format(label, completed.returncode))
            return completed.returncode
        except FileNotFoundError as exc:
            self.audit("command_missing", "{} {}".format(label, exc))
            self.actions.append("{} skipped: command missing".format(label))
            return 127
        except subprocess.SubprocessError as exc:
            self.audit("command_error", "{} {}".format(label, exc))
            return 124


def make_json(result):
    return json.dumps(result, indent=2, sort_keys=False) + "\n"


def make_sarif(result):
    verdict = result["verdict"]
    level = "error" if verdict["vulnerable"] else "warning" if verdict["exit_code"] == EXIT_MITIGATED else "note"
    results = []
    if verdict["status"] in ("vulnerable_confirmed_functional", "unverified",
                              "mitigated_modprobe", "mitigated_initcall"):
        results.append({
            "ruleId": RULE_ID,
            "level": level,
            "message": {"text": verdict["summary"]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": "file:///proc/version"}
                }
            }],
        })
    for warning in result["checks"]["modprobe_mitigation"].get("warnings", []):
        results.append({
            "ruleId": RULE_ID,
            "level": "warning",
            "message": {"text": warning},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": "file:///etc/modprobe.d/"}
                }
            }],
        })
    return json.dumps({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": TOOL_NAME,
                    "version": VERSION,
                    "informationUri": INFO_URI,
                    "rules": [{
                        "id": RULE_ID,
                        "name": "Copy Fail Linux AF_ALG exposure",
                        "shortDescription": {"text": "Detects CVE-2026-31431 Copy Fail exposure"},
                        "fullDescription": {
                            "text": "Detects AF_ALG and algif_aead exposure to CVE-2026-31431 and reports patch or mitigation status."
                        },
                        "helpUri": REPOSITORY_URL,
                        "defaultConfiguration": {"level": "error"},
                    }],
                }
            },
            "results": results,
        }],
    }, indent=2, sort_keys=False) + "\n"


def make_human(result, use_color=True):
    verdict = result["verdict"]
    checks = result["checks"]
    host = result["host"]
    if verdict["vulnerable"]:
        verdict_color = "red"
    elif verdict["exit_code"] == EXIT_MITIGATED:
        verdict_color = "yellow"
    else:
        verdict_color = "green"
    lines = [
        colorize("BleedWatch copy-fail-check v{}".format(VERSION), "bold", use_color),
        "Detection and remediation toolkit for {}".format(CVE_ID),
        "",
        "Environment",
        "  Host: {}".format(host["hostname"]),
        "  OS: {} {} ({})".format(host["os"]["distro"], host["os"]["version"], host["os"]["family"]),
        "  Kernel: {}".format(host["kernel"]["version"]),
        "",
        "Kernel",
        "  Patch status: {}".format(host["kernel"]["patch_status"]),
        "  Patch evidence (authoritative): {}".format(checks["kernel_patch"]["evidence"] or "none"),
        "  Weak signal (informational only): {}".format(checks["kernel_patch"].get("weak_evidence") or "none"),
        "",
        "AF_ALG Status",
        "  Syscall: {}".format(checks["af_alg_syscall"]["status"]),
        "  Functional test: {}".format(checks["functional_test"]["status"]),
        "  Loaded modules: {}".format(", ".join(checks["modules_loaded"]) or "none detected"),
        "",
        "Module Provenance (modprobe blacklist only works for 'loadable')",
        "  af_alg: {}".format(checks.get("module_provenance", {}).get("af_alg", "unknown")),
        "  algif_aead: {}".format(checks.get("module_provenance", {}).get("algif_aead", "unknown")),
        "  Any built-in: {}".format(str(checks.get("module_provenance", {}).get("any_builtin", False)).lower()),
        "",
        "Modprobe Mitigation",
        "  Present: {}".format(str(checks["modprobe_mitigation"]["present"]).lower()),
        "  Completeness: {}".format(checks["modprobe_mitigation"]["completeness"]),
        "  Files: {}".format(", ".join(checks["modprobe_mitigation"]["files"]) or "none"),
        "",
        "Kernel Boot Mitigation (RHEL official, requires reboot)",
        "  initcall_blacklist tokens: {}".format(
            ", ".join(checks.get("kernel_boot_mitigation", {}).get("initcall_blacklist", []) or []) or "none"),
        "  Blocks Copy Fail: {}".format(
            str(checks.get("kernel_boot_mitigation", {}).get("blocks_copy_fail", False)).lower()),
        "",
        "Verdict",
        "  {}".format(colorize(verdict["summary"], verdict_color, use_color)),
        "  Exit code: {}".format(verdict["exit_code"]),
    ]
    if verdict["recommendations"]:
        lines.append("  Recommendations:")
        for recommendation in verdict["recommendations"]:
            lines.append("    - {}".format(recommendation))
    lines.extend([
        "",
        "GitHub: {}".format(REPOSITORY_URL),
        "Star the repository to follow Copy Fail mitigation updates.",
    ])
    return "\n".join(lines) + "\n"


def emit_output(text, output_file):
    if output_file:
        with open(output_file, "w", encoding="utf-8") as handle:
            handle.write(text)
    else:
        sys.stdout.write(text)


def build_parser():
    parser = argparse.ArgumentParser(description="Detect and remediate CVE-2026-31431 Copy Fail exposure")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="run read-only detection (default)")
    mode.add_argument("--audit", action="store_true",
                      help="alias of --check; reserved for future detailed diagnostic scoring (changelog probe is now always on)")
    mode.add_argument("--remediate", action="store_true", help="apply AF_ALG modprobe mitigation after confirmation")
    mode.add_argument("--verify", action="store_true", help="verify an earlier remediation")
    parser.add_argument("--json", action="store_true", help="emit structured JSON")
    parser.add_argument("--sarif", action="store_true", help="emit SARIF 2.1.0 JSON")
    parser.add_argument("--quiet", action="store_true", help="suppress human-readable output")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    parser.add_argument("--output-file", help="write output to a file")
    parser.add_argument("--version", action="store_true", help="print version and exit")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.version:
        print("{} {}".format(TOOL_NAME, VERSION))
        return EXIT_SAFE
    if sys.version_info < (3, 8):
        sys.stderr.write("Python 3.8 or newer is required\n")
        return EXIT_RUNTIME_ERROR

    if args.remediate:
        remediator = CopyFailRemediator()
        code, message = remediator.remediate()
        if not args.quiet:
            result = {
                "tool": TOOL_NAME,
                "version": VERSION,
                "timestamp": utc_now_z(),
                "remediation": {
                    "exit_code": code,
                    "summary": message,
                    "actions": remediator.actions,
                    "warnings": remediator.warnings,
                },
            }
            if args.json:
                emit_output(make_json(result), args.output_file)
            elif args.sarif:
                detector_result = CopyFailDetector(functional_test=False).detect()
                emit_output(make_sarif(detector_result), args.output_file)
            else:
                lines = [message]
                lines.extend(remediator.actions)
                lines.extend("warning: {}".format(warning) for warning in remediator.warnings)
                emit_output("\n".join(lines) + "\n", args.output_file)
        return code

    detector = CopyFailDetector(functional_test=not args.verify)
    result = detector.detect()
    if not args.quiet:
        if args.json:
            output = make_json(result)
        elif args.sarif:
            output = make_sarif(result)
        else:
            use_color = not args.no_color and "NO_COLOR" not in os.environ
            output = make_human(result, use_color)
        emit_output(output, args.output_file)
    return result["verdict"]["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
