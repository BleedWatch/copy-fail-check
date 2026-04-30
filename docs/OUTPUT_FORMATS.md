# Output Formats

## JSON

JSON output is emitted with deterministic key order and UTC timestamps using an ISO 8601 `Z` suffix.

Required top-level fields:

| Field | Type | Description |
| --- | --- | --- |
| `tool` | string | Always `copy-fail-check`. |
| `version` | string | Tool semantic version. |
| `timestamp` | string | UTC timestamp such as `2026-04-30T14:23:45Z`. |
| `host` | object | Hostname, OS metadata, and kernel patch status. |
| `checks` | object | AF_ALG, functional sentinel, module, modprobe, and patch evidence. |
| `verdict` | object | Stable status, vulnerability boolean, exit code, summary, and recommendations. |

Example:

```json
{
  "tool": "copy-fail-check",
  "version": "1.0.0",
  "timestamp": "2026-04-30T14:23:45Z",
  "host": {
    "hostname": "ci-runner-1",
    "os": {"distro": "ubuntu", "version": "24.04", "codename": "noble", "family": "debian"},
    "kernel": {"version": "6.8.0-39-generic", "patch_status": "unverified"}
  },
  "checks": {
    "af_alg_syscall": {"status": "accessible", "errno": null, "detail": "AF_ALG socket creation succeeded"},
    "modules_loaded": [],
    "modprobe_mitigation": {"present": false, "files": [], "completeness": "none", "warnings": []},
    "kernel_patch": {"detected": false, "evidence": null}
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

## SARIF

SARIF output conforms to the required SARIF 2.1.0 shape and uses schema URI <https://json.schemastore.org/sarif-2.1.0.json>. The official SARIF specification is published at <https://docs.oasis-open.org/sarif/sarif/v2.1.0/>.

The tool emits:

- `version`
- `$schema`
- `runs[].tool.driver.name`
- `runs[].tool.driver.version`
- `runs[].tool.driver.informationUri`
- `runs[].tool.driver.rules[]`
- `runs[].results[]`

The rule id is `BLEEDWATCH-CVE-2026-31431`. Results use `file:///proc/version` for kernel evidence or `file:///etc/modprobe.d/` for mitigation configuration findings.
