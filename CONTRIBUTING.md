# Contributing

Thank you for contributing to `copy-fail-check`.

Keep patches focused and security-oriented. The command-line contract, exit codes, output schemas, and stdlib-only implementation are compatibility surfaces for operators and CI systems, so changes to them need clear rationale and tests.

## Development

```bash
python3 -m unittest discover -s tests -v
python3 copy-fail-check.py --check --json | python3 -m json.tool >/dev/null
python3 copy-fail-check.py --check --sarif | python3 -m json.tool >/dev/null
```

Do not add runtime dependencies. The shipped detector and remediator logic must remain in `copy-fail-check.py`.
