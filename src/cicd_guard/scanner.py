from __future__ import annotations

import re
from typing import Any

PINNED_SHA = re.compile(r"@[a-f0-9]{40}$")
SECRET_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|secret|token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{12,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
]
DANGEROUS_COMMAND_PATTERNS = {
    "remote script piped to shell": re.compile(r"\b(curl|wget)\b[^\n|]*\|\s*(bash|sh)\b", re.IGNORECASE),
    "world-writable permissions": re.compile(r"\bchmod\s+777\b", re.IGNORECASE),
    "error suppression": re.compile(r"\bset\s+\+e\b", re.IGNORECASE),
}


def scan_workflow(workflow: dict[str, Any], raw_text: str = "") -> list[dict[str, str]]:
    """Scan a GitHub Actions workflow for common CI/CD security risks."""
    findings: list[dict[str, str]] = []
    findings.extend(_scan_permissions(workflow))
    findings.extend(_scan_jobs(workflow.get("jobs", {})))
    findings.extend(_scan_raw_text(raw_text))
    return findings


def _scan_permissions(workflow: dict[str, Any]) -> list[dict[str, str]]:
    permissions = workflow.get("permissions")
    if permissions == "write-all":
        return [_finding("high", "Workflow grants write-all permissions", "Use least-privilege permissions at workflow or job level.")]
    if permissions is None:
        return [_finding("medium", "Workflow does not explicitly define permissions", "Set explicit read-only permissions by default and elevate per job only when needed.")]
    return []


def _scan_jobs(jobs: dict[str, Any]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for job_name, job in jobs.items():
        for step in job.get("steps", []):
            uses = step.get("uses")
            run = step.get("run", "")
            if uses and not _is_pinned_action(str(uses)):
                findings.append(_finding("medium", f"Action is not pinned to a full commit SHA: {uses}", "Pin third-party actions to a trusted full-length commit SHA."))
            if isinstance(run, str):
                for label, pattern in DANGEROUS_COMMAND_PATTERNS.items():
                    if pattern.search(run):
                        findings.append(_finding("high", f"Dangerous shell pattern found in job {job_name}: {label}", "Replace unsafe shell patterns with verified scripts and integrity checks."))
    return findings


def _scan_raw_text(raw_text: str) -> list[dict[str, str]]:
    findings = []
    for pattern in SECRET_PATTERNS:
        if pattern.search(raw_text):
            findings.append(_finding("critical", "Potential secret material found in workflow file", "Move secrets to GitHub Actions secrets or an approved secret manager."))
            break
    return findings


def _is_pinned_action(uses: str) -> bool:
    if uses.startswith("./"):
        return True
    return bool(PINNED_SHA.search(uses))


def _finding(severity: str, finding: str, recommendation: str) -> dict[str, str]:
    return {"severity": severity, "finding": finding, "recommendation": recommendation}
