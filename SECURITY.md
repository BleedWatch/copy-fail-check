# Security Policy

## Reporting a Vulnerability

Report security issues affecting `copy-fail-check` to security@bleedwatch.com. Include the affected version, operating system, reproduction steps, and any logs or command output that help confirm impact.

BleedWatch follows a 90-day coordinated disclosure policy for vulnerabilities in this project. We acknowledge new reports within 5 business days, provide status updates during triage, and publish fixes plus advisories once remediation is available or the disclosure window expires.

Do not disclose suspected vulnerabilities publicly until BleedWatch has had a reasonable opportunity to investigate and release a fix.

## Scope

In scope:

- Vulnerabilities in `copy-fail-check.py`
- Unsafe remediation behavior
- Incorrect vulnerability verdicts that could create material security risk
- CI, documentation, or packaging issues that could mislead operators

Out of scope:

- Reports about CVE-2026-31431 itself
- Denial-of-service issues requiring malicious local modification of this repository
- Findings that depend on unsupported Python or operating system versions

## Supported Versions

| Version | Supported |
| --- | --- |
| 1.0.x | Yes |
