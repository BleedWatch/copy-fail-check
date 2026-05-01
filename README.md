# copy-fail-check: CVE-2026-31431 Copy Fail Detection and Remediation

> **⚠️ ADVISORY — v1.0.0 yanked**
>
> Version 1.0.0 can incorrectly report "Non vulnerable" by inferring
> patch status from the kernel mainline version rather than from
> verified fix evidence. This affects Fedora and any distro running
> stable kernel branches below 7.0-rc7 unless the vendor fix or
> backport is explicitly confirmed. Independently of that heuristic,
> the v1.0.0 functional test is also incomplete and never executes
> the full Copy Fail primitive (sendmsg + splice + recv), so it
> returns "no_modification" on every kernel regardless of state.
>
> **Distrust every v1.0.0 "Non vulnerable" verdict** unless it has
> been independently verified. Re-test with v1.1.0+ once released.
>
> Tracking: GitHub issue #1. v1.1.0 in progress.

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

## Detection Methodology

The detector combines four signals: kernel patch evidence (parsed from `/proc/version`, `uname`, and optional package changelogs), AF_ALG socket reachability, currently loaded `algif_*` modules, and modprobe blacklist or `install ... /bin/false` directives. The functional sentinel test only verifies that the AF_ALG `authencesn` primitive can be created and bound on a self-owned `/tmp/` file; it deliberately does **not** ship a weaponised splice payload that would trigger the actual page cache write. This avoids redistributing a working LPE primitive while still allowing the verdict logic to flag a host as `vulnerable_inferred_kernel` (exit code `2`) whenever AF_ALG is reachable and no patch evidence is found. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full rationale.

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
