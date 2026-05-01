# copy-fail-check: CVE-2026-31431 Copy Fail Detection and Remediation

> **⚠️ v1.0.0 yanked — upgrade to v1.1.1+**
>
> v1.0.0 produced false negatives on Fedora and similar distros (kernel
> mainline-version heuristic + an incomplete functional test that never
> drove the AF_ALG primitive). v1.1.0 shipped the full sendmsg + splice +
> recv chain, dropped the version heuristic, and reports `UNVERIFIED`
> rather than `PATCHED` whenever authoritative evidence is missing. v1.1.1
> closes a follow-up gap on RHEL 8/9/10 where `algif_aead` is **compiled
> into the kernel** (CONFIG=y), making any modprobe-based mitigation
> silently inert. v1.1.1 detects built-in modules, refuses misleading
> modprobe remediation, and recognizes Red Hat's official
> `initcall_blacklist=` boot-arg mitigation. See the
> [CHANGELOG](CHANGELOG.md) and
> [issue #1](https://github.com/BleedWatch/copy-fail-check/issues/1) for
> the full root-cause analysis.

[![Tests](https://github.com/bleedwatch/copy-fail-check/actions/workflows/test.yml/badge.svg)](https://github.com/bleedwatch/copy-fail-check/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](copy-fail-check.py)
[![Awesome](https://img.shields.io/badge/awesome-inclusion%20pending-lightgrey.svg)](https://github.com/sindresorhus/awesome)

Detection and remediation toolkit for CVE-2026-31431 (Copy Fail).

## What Is Copy Fail?

Copy Fail Linux is CVE-2026-31431, a Linux kernel LPE 2026 issue in the `authencesn` AEAD IPsec ESN crypto template reachable through AF_ALG sockets and `splice()`. In vulnerable kernels, `algif_aead` can operate in-place and permit a controlled 4-byte write into the page cache of a readable file. The practical result is a deterministic local privilege escalation primitive on common Linux distributions when the vulnerable code path is exposed.

This is different from Dirty Pipe or Dirty Cow in an operational sense: Copy Fail is described as deterministic, does not rely on a race, and crosses container boundaries because the page cache is shared by the host kernel. A container is therefore not a reliable security boundary for this class of AF_ALG vulnerability.

`copy-fail-check` provides Copy Fail detection, Copy Fail remediation, and Copy Fail patch verification without external Python dependencies. The functional safety check only uses a self-owned sentinel under `/tmp/`; it never targets `/usr/bin/su`, `/etc/passwd`, or any system file. For background research, see Theori/Xint material and <https://copy.fail>.

## Quick Start

```bash
# Detection (read-only, safe to run anywhere)
curl -sSL https://raw.githubusercontent.com/bleedwatch/copy-fail-check/main/copy-fail-check.py | python3 -

# Or clone for full audit
git clone https://github.com/bleedwatch/copy-fail-check
cd copy-fail-check
sudo python3 copy-fail-check.py --audit

# Remediation (requires root, prompts for confirmation)
sudo python3 copy-fail-check.py --remediate
```

## Modes

| Mode or option | Behavior | Typical exit codes |
| --- | --- | --- |
| `--check` | Read-only detection, default mode | `0`, `2`, `3`, `10`, `11` |
| `--audit` | Detection plus deeper package and mitigation diagnostics | `0`, `2`, `3`, `10`, `11` |
| `--remediate` | Writes AF_ALG modprobe mitigation after confirmation | `20`, `21`, `22` |
| `--verify` | Verifies previous remediation without functional exploit attempt | `0`, `2`, `3`, `10`, `11` |
| `--json` | Deterministic JSON output | Same as selected mode |
| `--sarif` | SARIF 2.1.0 output for code scanning systems | Same as selected mode |
| `--quiet` | Suppresses stdout; scripts can rely on exit code | Same as selected mode |

Automation can set `BLEEDWATCH_AUTO_CONFIRM=1` for non-interactive remediation. Use it only inside controlled configuration management.

## Output Formats

JSON output is stable and suitable for CI gates:

```json
{
  "tool": "copy-fail-check",
  "version": "1.0.0",
  "timestamp": "2026-04-30T14:23:45Z",
  "host": {
    "hostname": "runner",
    "os": {"distro": "ubuntu", "version": "24.04", "codename": "noble", "family": "debian"},
    "kernel": {"version": "6.8.0-39-generic", "patch_status": "unverified"}
  },
  "verdict": {
    "status": "vulnerable_inferred_kernel",
    "vulnerable": true,
    "exit_code": 2,
    "summary": "Vulnerable inferred - AF_ALG accessible and patch evidence not found",
    "recommendations": ["Patch the kernel or run sudo python3 copy-fail-check.py --remediate"]
  }
}
```

SARIF output uses rule id `BLEEDWATCH-CVE-2026-31431` and can be uploaded to GitHub Code Scanning.

## CI Integration

GitHub Actions:

```yaml
- name: Copy Fail patch verification
  run: |
    curl -sSL https://raw.githubusercontent.com/bleedwatch/copy-fail-check/main/copy-fail-check.py -o copy-fail-check.py
    python3 copy-fail-check.py --check --json
```

GitLab CI:

```yaml
copy_fail_check:
  image: python:3.12-slim
  script:
    - curl -sSL https://raw.githubusercontent.com/bleedwatch/copy-fail-check/main/copy-fail-check.py -o copy-fail-check.py
    - python3 copy-fail-check.py --check --json
```

Ansible:

```yaml
- name: Run Copy Fail detection
  ansible.builtin.command: python3 /usr/local/bin/copy-fail-check.py --check --json
  register: copy_fail
  changed_when: false
  failed_when: copy_fail.rc not in [0, 2, 3]
```

## Supported Platforms

| Platform | Versions | Detection | Remediation |
| --- | --- | --- | --- |
| Ubuntu | 20.04, 22.04, 24.04 | Supported | `update-initramfs -u` |
| Debian | 11, 12 | Supported | `update-initramfs -u` |
| RHEL compatible | 8, 9 | Supported | `dracut -f` |
| Fedora | Current maintained releases | Supported | `dracut -f` |
| SUSE | SLES/openSUSE 15+ | Supported | `dracut -f` or `mkinitrd` |
| Amazon Linux | 2, 2023 | Supported | `dracut -f` |

## Verdict and Exit Codes

| Exit | Verdict status | Meaning |
| --- | --- | --- |
| `0` | `patched` | Functional test reported no modification AND authoritative changelog evidence (rpm/apt) confirms the fix |
| `2` | `vulnerable_confirmed_functional` | Functional test detected the 4-byte controlled write — kernel is vulnerable (priority over all other signals) |
| `3` | `mitigated_modprobe` | AF_ALG syscall blocked by modprobe blacklist or `install /bin/false` (only valid when modules are loadable, not built-in) |
| `3` | `mitigated_initcall` | Kernel booted with `initcall_blacklist=algif_aead_init` / `af_alg_init` / `crypto_authenc_esn_module_init` (Red Hat official mitigation for kernels with built-in `algif_aead`) |
| `10` | `detection_error` | AF_ALG syscall returned an unexpected error; detection inconclusive |
| `11` | `unverified` | Functional test reported no modification but no authoritative changelog evidence — **never trust as patched without manual verification** |
| `11` | runtime_error | Unsupported environment (non-Linux, missing /proc, unsupported distro, Python < 3.8) |

Exit `11` covers both `unverified` and runtime errors; the `verdict.status` field in JSON output carries the precise distinction. Both indicate "non-conclusive, please re-investigate".

## Detection Methodology

The detector combines four signals:

1. **Functional Copy Fail primitive** (priority): runs the full AF_ALG `authencesn(hmac(sha1),cbc(aes))` chain — `ALG_SET_KEY` with rtattr-wrapped authenc key, `accept` op socket, `sendmsg(MSG_MORE)` with controlled AAD, `splice(sentinel → pipe → op socket)`, then `recv()` to drive the in-place AEAD decrypt — against a caller-owned 4 KiB sentinel under `/tmp/`. On vulnerable kernels the buggy 4-byte scratch write lands inside the spliced page cache; the tool detects the byte difference and reports the offset (typically offset 12). On patched kernels the in-place destination is rejected before the copyback and the page cache is left strictly unchanged.
2. **Authoritative kernel changelog** parsed from `rpm -q --changelog kernel-core-<release>` (Fedora), `rpm -q --changelog kernel-<release>` (RHEL/CentOS/Alma/Rocky/Amazon Linux), `rpm -q --changelog kernel-default-<release>` (SUSE), or `apt changelog linux-image-<release>` (Debian/Ubuntu) — every probe is pinned to the running `uname -r` so a freshly installed-but-not-yet-booted patched package cannot mask an older vulnerable kernel still in memory. Only authoritative changelog evidence drives a `patched` verdict.
3. **AF_ALG syscall reachability** (with EAFNOSUPPORT meaning blocked → exit 3 mitigated).
4. **Modprobe blacklist / install `/bin/false`** directives in `/etc/modprobe.d/`.

The sentinel is created with `O_CREAT|O_EXCL|O_NOFOLLOW` at `0600`, named with PID + nanosecond timestamp + 8 random bytes. Cleanup is guaranteed via `atexit` and signal handlers (SIGINT/SIGTERM). The functional test never opens, reads, writes, or unlinks any file outside `/tmp/`. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full rationale.

## RHEL / Built-in Modules

RHEL 8/9/10 (and most enterprise rebuilds — Alma, Rocky) ship `af_alg` and `algif_aead` **compiled into the kernel image** (`CONFIG_CRYPTO_USER_API_AEAD=y`). On those systems the modprobe blacklist approach is silently ignored by the kernel — `/etc/modprobe.d/` is consulted only for loadable modules. The detector parses `/lib/modules/<release>/modules.builtin` to identify this case and reports it under `module_provenance`.

When built-in modules are detected, three mitigation paths are available:

1. **Kernel boot argument (Red Hat official, requires reboot)** — append one of the following to `GRUB_CMDLINE_LINUX` and run `grub2-mkconfig -o /boot/grub2/grub.cfg` (or `update-grub` on Debian-family):
   ```
   initcall_blacklist=algif_aead_init               # block only the affected algif backend
   initcall_blacklist=af_alg_init                   # block AF_ALG entirely (broader)
   initcall_blacklist=crypto_authenc_esn_module_init # block only the affected algorithm
   ```
   Reference: <https://access.redhat.com/security/cve/cve-2026-31431>. The detector recognizes any of these tokens in `/proc/cmdline` and returns `mitigated_initcall` (exit 3).

2. **Vendor kernel update** — once Red Hat ships the backport for the running RHEL stream, apply it via `dnf update kernel` and reboot. The detector's changelog probe will pick up the fix automatically.

3. **eBPF LSM blocker (no reboot, requires `CONFIG_BPF_LSM=y` and `bpf` in `/sys/kernel/security/lsm`)** — deploy a `socket_create` LSM hook that returns `-EPERM` for `family=AF_ALG`. A reference implementation lives at <https://github.com/lestercheung/linux-copy-fail-workarounds>. **Caveat:** at the time of this audit (2026-05-01), `block_af_alg.c` in that repo omits the trailing `int ret` argument from the BPF LSM hook signature and does not preserve prior denials, which can interfere with other BPF LSM programs in the chain. Patch the hook signature before production deployment, persist the link via systemd or BPF pinning so the mitigation survives loader exit.

`copy-fail-check --remediate` performs a pre-flight check and refuses to write a misleading modprobe file when the modules are built-in, instead emitting these three options as remediation `warnings`.

## Why This Tool Exists

While distro patches are the primary remediation path, kernel patch propagation is uneven and can take days. This tool provides immediate verification and a defense-in-depth modprobe-level mitigation that closes the attack surface regardless of patch state.

BleedWatch’s position is direct: kernel-shared multi-tenancy is no longer an acceptable security boundary on its own. Self-hosted CI/CD runners, AI agent fleets, and multi-tenant Kubernetes nodes need continuous verification of host-level attack surfaces, not only container image scanning.

## About BleedWatch

BleedWatch is a French cybersecurity ISV building EASM and supply chain security tooling for CI/CD pipelines. This detector is a small piece of a broader thesis: shared-kernel multi-tenancy is the new attack surface. We are working on a CI/CD Scanner that continuously audits your supply chain for risks like these. ⭐ Star this repository at <https://github.com/BleedWatch/copy-fail-check> to follow Copy Fail mitigation updates and the broader BleedWatch tooling roadmap.

## Security Disclosure

Please report suspected vulnerabilities in this project through the process in [SECURITY.md](SECURITY.md).

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) and keep changes dependency-free unless the discussion explicitly changes that project contract.

Copyright 2026 BleedWatch SASU. RCS registration details will be published with the public repository. Follow BleedWatch on LinkedIn.
