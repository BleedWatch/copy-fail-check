# Architecture

`copy-fail-check` is intentionally small, auditable, and operationally conservative. It exists to answer one question for operators: is this Linux host exposed to CVE-2026-31431 Copy Fail, and can the AF_ALG attack surface be closed immediately while vendor kernel patches propagate?

## Single-file design

The detector and remediator ship as one executable Python file so the common incident-response path remains viable: `curl` the script, inspect it, and run it with the system Python. A single file also reduces packaging ambiguity for emergency use on minimal servers, locked-down CI runners, and short-lived cloud instances. Tests and documentation live outside the script, but runtime logic stays in `copy-fail-check.py`.

## Stdlib-only design

The runtime has zero external dependencies. That keeps supply-chain risk low, makes offline execution straightforward, and lets reviewers audit every imported module with a simple `grep` against the Python standard library. The tool uses raw ANSI sequences for color and JSON/TOML-friendly structures instead of pulling in convenience packages.

## Conservative remediation

Read-only detection is the default. `--remediate` is explicit, requires root, and asks the operator to type `CONFIRM` unless `BLEEDWATCH_AUTO_CONFIRM=1` is present for controlled automation. The tool does not provide an automatic default fix path because host kernel mitigation changes boot-time module policy and initramfs state. Operators should never be surprised by such changes.

## Sentinel safety

The functional check uses a uniquely named sentinel under `/tmp/` with `O_EXCL`, `O_NOFOLLOW` where available, and `0600` permissions. The path includes the process id, nanosecond timestamp, and a `secrets.token_hex(8)` random token. The test hardcodes offset `0` of the sentinel inode’s own page cache and asserts the path starts with `/tmp/` before attempting the AF_ALG primitive. It never touches `/usr/bin/su`, `/etc/passwd`, or any system file.

Cleanup is handled in three layers: `try/finally`, signal handlers for `SIGINT` and `SIGTERM`, and an `atexit` registration. If setup fails because `/tmp` is not writable, AF_ALG is unavailable, or the crypto primitive cannot be reached, the detector falls back to syscall, module, modprobe, and kernel patch analysis. It does not claim a host is safe merely because the functional setup could not run.

## Detection methodology and no-weaponised-payload policy

The functional check probes whether the AF_ALG `authencesn(hmac(sha1),cbc(aes))` socket can be created and bound. It does **not** perform the full splice-based crypto operation that triggers the in-place write described by CVE-2026-31431. Distributing a weaponised primitive in a public defensive tool would lower the bar for opportunistic exploitation and is at odds with responsible disclosure during the early days of a CVE rollout.

As a result, on a vulnerable kernel the functional check usually reports `no_modification`. The verdict is not based on that alone: the tool combines AF_ALG availability, kernel patch evidence, modprobe mitigation completeness, and module load state to produce the final exit code. When AF_ALG is reachable and no patch evidence exists, the verdict is `vulnerable_inferred_kernel` and the exit code is `2`, regardless of whether the functional probe found a modification. The `vulnerable_confirmed_functional` verdict and the corresponding `modification_detected` status are reserved for environments where an operator wires in a stronger probe out of band, or where another process has already modified the sentinel.

Operators who need a fully weaponised verification primitive must source it separately and audit it themselves. This project will not bundle one.

## Repository visibility decision

BleedWatch’s global workspace policy defaults repositories to private. This repository is an explicit exception because the brief requires a public open-source security tool for community benefit and a transparent funnel to BleedWatch CI/CD Scanner. The repository should be created manually as `bleedwatch/copy-fail-check` with public visibility after review.
