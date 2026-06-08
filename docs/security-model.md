# CI/CD Security Model

## Objective

Identify risky GitHub Actions workflow patterns before they become software supply-chain issues.

## Control areas

| Control Area | Scanner Coverage |
|---|---|
| Least privilege | Flags missing explicit permissions and write-all permissions |
| Dependency integrity | Flags third-party actions not pinned to a full commit SHA |
| Secret hygiene | Flags potential hardcoded secrets in workflow files |
| Unsafe execution | Flags risky shell patterns such as curl piped to shell |
| Remediation readiness | Each finding includes a recommendation |

## Severity model

- `critical`: potential secret exposure
- `high`: write-all permissions or dangerous shell execution
- `medium`: missing permissions or unpinned actions

## Employer-facing explanation

This project demonstrates DevSecOps security engineering by turning CI/CD hardening standards into automated checks. It can be extended into a pull-request gate, repository scanner, or compliance evidence generator.
