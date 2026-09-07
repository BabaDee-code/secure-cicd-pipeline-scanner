# CI/CD Security Model

## Objective

Identify risky GitHub Actions workflow patterns before they become software supply-chain issues.

## Control areas

| Control Area | Scanner Coverage |
|---|---|
| Least privilege | Flags missing explicit permissions and `write-all` permissions |
| Dependency integrity | Flags third-party actions not pinned to a full commit SHA |
| Secret hygiene | Flags potential hardcoded secrets in workflow files |
| Unsafe execution | Flags risky shell patterns such as remote scripts piped to a shell |
| Pull request trust boundaries | Flags privileged `pull_request_target` workflows that check out untrusted PR head code |
| Expression injection | Flags direct interpolation of untrusted PR title/body metadata into `run:` shell commands |
| Remediation readiness | Each finding includes a recommendation |

## Pull request trust model

GitHub Actions workflows cross a trust boundary when code or metadata from an external pull request is evaluated in a repository-owned workflow. Two patterns deserve special attention:

1. **Privileged PR execution:** `pull_request_target` executes in the context of the base repository. It is useful for trusted automation, but checking out and executing the contributor's head ref can expose repository-scoped credentials or permissions to untrusted code. The scanner treats this as `critical`.
2. **Expression-to-shell injection:** Pull request titles and bodies are contributor-controlled strings. Embedding `${{ github.event.pull_request.title }}` or `${{ github.event.pull_request.body }}` directly in a `run:` command allows that value to become part of the generated shell script. The scanner treats this as `high` and recommends passing the value through an environment variable and quoting it in the shell.

The scanner intentionally does not flag `pull_request_target` by itself. A privileged event can be safe when it stays on trusted base-repository code and does not execute untrusted PR content.

## Severity model

- `critical`: potential secret exposure or privileged execution of untrusted pull request code
- `high`: `write-all` permissions, dangerous shell execution, or direct untrusted PR metadata interpolation into shell commands
- `medium`: missing permissions or unpinned actions

## Employer-facing explanation

This project demonstrates DevSecOps security engineering by converting CI/CD trust boundaries and software supply-chain hardening standards into deterministic, testable policy checks. It can be extended into a pull-request gate, repository scanner, or compliance evidence generator.
