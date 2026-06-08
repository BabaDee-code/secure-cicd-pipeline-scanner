# Secure CI/CD Pipeline Scanner

![CI](https://github.com/BabaDee-code/secure-cicd-pipeline-scanner/actions/workflows/ci.yml/badge.svg)

A DevSecOps security scanner that reviews GitHub Actions workflows for excessive permissions, unpinned third-party actions, exposed secret patterns, weak artifact controls, and insecure CI/CD patterns. This project is designed as a safe, testable portfolio tool for software supply-chain security.

## What this project shows

- GitHub Actions workflow security review
- Excessive permissions detection
- Unpinned action detection
- Secret-pattern detection in workflow files
- Dangerous shell command pattern detection
- Risk scoring and remediation recommendations
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
pytest -q
python -m cicd_guard.scan samples/workflows/insecure-workflow.yml
```

## Example finding

```json
{
  "severity": "high",
  "finding": "Workflow grants write-all permissions",
  "recommendation": "Use least-privilege permissions at workflow or job level."
}
```

## Security controls represented

- Least-privilege CI/CD permissions
- Third-party action pinning
- Secret hygiene
- Build pipeline integrity
- Secure artifact handling
- Automated policy checks

## Portfolio talking points

This project demonstrates how I would secure CI/CD pipelines by converting software supply-chain risks into automated checks that can run in pull requests and prevent insecure workflow drift.
