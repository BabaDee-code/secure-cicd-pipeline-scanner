# Secure CI/CD Pipeline Scanner

![CI](https://github.com/BabaDee-code/secure-cicd-pipeline-scanner/actions/workflows/ci.yml/badge.svg)

A DevSecOps security scanner that reviews GitHub Actions workflows for excessive permissions, unpinned third-party actions, exposed secret patterns, dangerous shell execution, and pull-request trust-boundary failures. This project is designed as a safe, testable portfolio tool for software supply-chain security.

## What this project shows

- GitHub Actions workflow security review
- Excessive permissions detection
- Unpinned action detection
- Secret-pattern detection in workflow files
- Dangerous shell command pattern detection
- `pull_request_target` trust-boundary analysis
- Direct PR metadata-to-shell interpolation detection
- Severity-based findings with remediation recommendations
- Unit tests and CI validation

## Repository structure

```text
src/cicd_guard/             CI/CD scanner engine and CLI
samples/workflows/          Sample secure and insecure workflows
tests/                      Unit tests
.github/workflows/ci.yml    Automated test workflow
docs/security-model.md      CI/CD security model and control mapping
```

## Run locally

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\\Scripts\\activate
pip install -r requirements-dev.txt
PYTHONPATH=src pytest -q
PYTHONPATH=src python -m cicd_guard.scan samples/workflows/insecure-workflow.yml
```

On Windows PowerShell, set `$env:PYTHONPATH = "src"` before running the test or CLI commands.

## Example finding

```json
{
  "severity": "critical",
  "finding": "pull_request_target job review checks out untrusted pull request code",
  "recommendation": "Do not execute pull request head code in pull_request_target. Use pull_request for untrusted code, or keep the privileged workflow on trusted base-repository code only."
}
```

## Security controls represented

- Least-privilege CI/CD permissions
- Third-party action pinning
- Secret hygiene
- Build pipeline integrity
- Pull-request trust-boundary enforcement
- Expression-injection prevention
- Automated policy checks

See [`docs/security-model.md`](docs/security-model.md) for the threat model and severity rationale.

## Portfolio talking points

This project demonstrates how I would secure CI/CD pipelines by converting software supply-chain risks and GitHub Actions trust boundaries into deterministic checks that can run in pull requests and prevent insecure workflow drift.
