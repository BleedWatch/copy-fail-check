# Exit Codes

`copy-fail-check` exit codes are stable. CI systems and configuration management should treat them as an API.

| Code | Meaning | Typical scenario |
| --- | --- | --- |
| `0` | Non vulnerable | Kernel patch evidence is present, or AF_ALG is blocked and no vulnerable exposure is reachable. |
| `2` | Vulnerable | Functional sentinel test detected modification, or AF_ALG is accessible and patch evidence is absent. |
| `3` | Vulnerable but mitigated | Kernel patch evidence is absent, but AF_ALG is blocked by syscall behavior or complete modprobe mitigation. |
| `10` | Detection error | AF_ALG probing or host inspection failed in a way that prevents a reliable verdict. |
| `11` | Runtime error | Unsupported OS, unsupported distribution, inaccessible `/proc`, or Python version below 3.8. |
| `20` | Remediation applied | `--remediate` wrote or confirmed mitigation and post-check accepted the state. Reboot is recommended. |
| `21` | Remediation cancelled | Operator did not type the exact confirmation string. |
| `22` | Remediation failed | Root privileges, filesystem writes, command execution, or post-check failed. |

`--quiet` suppresses output but keeps these exit codes unchanged.
