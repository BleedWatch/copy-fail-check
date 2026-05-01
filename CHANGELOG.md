# Changelog

All notable changes to this project are documented in this file. The project follows semantic versioning.

## [1.1.0] - 2026-05-01

### Critical fix

- Removed unsafe mainline-version heuristic (`LAST_UNFIXED_MAINLINE` and
  `kernel_tuple()`) that caused false negatives on Fedora and other distros
  running stable branches below 7.0 with potential vendor backports. (#1)
- Reimplemented the functional test to actually execute the Copy Fail
  primitive: AF_ALG `authencesn(hmac(sha1),cbc(aes))` → `ALG_SET_KEY` with
  rtattr-wrapped authenc key → `accept` op socket → `sendmsg(MSG_MORE)`
  with controlled AAD → `splice(sentinel → pipe → op socket)` → `recv()`
  drives the in-place AEAD decrypt that triggers the buggy 4-byte scratch
  write on vulnerable kernels. Non-destructive port of the Theori PoC,
  operating exclusively on a caller-owned `/tmp` sentinel. v1.0.0 only
  opened an AF_ALG socket without driving the chain, so it returned
  `no_modification` on every kernel. (#1)
- Verdict matrix tightened: absence of changelog evidence + functional
  test reporting no modification now reports `UNVERIFIED` (exit 11), not
  `PATCHED`. The tool no longer infers "patched" from missing data.
- `kernel_patch.detected` is now driven exclusively by authoritative
  package-changelog evidence; build-string token matches are surfaced as
  informational `weak_evidence` and do not influence the verdict.

### Improvements

- Changelog probe now covers Fedora's `kernel-core` package before the
  generic `kernel`, and queries `kernel-default` then `kernel` on SUSE.
- The changelog probe runs by default in `--check` mode, not just `--audit`
  (the `--audit` flag is preserved as a reserved alias for future detailed
  scoring; `deep_patch_check` is no longer a behavioral toggle).
- `modification_detected` now reports the byte offset and count of altered
  bytes (e.g. "modified at offset 12 (4 byte(s) altered)") matching the
  4-byte controlled-write characteristic of the CVE.
- `splice_compat` shim provides a libc.splice fallback via ctypes so the
  tool keeps the Python 3.8+ promise (`os.splice` was added in 3.10).
- CI matrix extended with a `fedora:43` job and a verdict-guard step that
  fails the build if `patched` is ever emitted without authoritative
  changelog evidence — encoding the v1.0.0 invariant violation as a CI
  gate.

### Yanked

- v1.0.0 yanked due to false negative on vulnerable Fedora 43 hosts.
  See issue #1 for the full root-cause analysis.

## [1.0.0] - 2026-04-30

### Added

- Single-file Python 3.8+ stdlib-only detector for CVE-2026-31431 Copy Fail.
- Read-only detection, audit, verification, JSON, SARIF, quiet, and output-file modes.
- Interactive AF_ALG modprobe remediation with audit logging and distro-aware initramfs rebuild.
- Unit tests for detector parsing, verdicts, sentinel cleanup, and remediation idempotence.
- Project documentation, issue templates, CI workflows, MIT license, and security policy.
