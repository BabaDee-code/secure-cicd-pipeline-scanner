import yaml

from cicd_guard.scanner import scan_workflow


def test_write_all_permissions_generate_high_finding():
    workflow = {"permissions": "write-all", "jobs": {}}
    findings = scan_workflow(workflow)
    assert findings[0]["severity"] == "high"
    assert "write-all" in findings[0]["finding"]


def test_job_write_all_permissions_generate_high_finding():
    workflow = {
        "permissions": {"contents": "read"},
        "jobs": {"release": {"permissions": "write-all", "steps": []}},
    }
    findings = scan_workflow(workflow)
    assert any(f["severity"] == "high" and "Job release grants write-all" in f["finding"] for f in findings)


def test_job_write_scopes_are_reported():
    workflow = {
        "permissions": {"contents": "read"},
        "jobs": {
            "publish": {
                "permissions": {"contents": "read", "packages": "write", "id-token": "write"},
                "steps": [],
            }
        },
    }
    findings = scan_workflow(workflow)
    permission_findings = [f for f in findings if "Job publish grants write permissions" in f["finding"]]
    assert len(permission_findings) == 1
    assert permission_findings[0]["severity"] == "medium"
    assert "id-token" in permission_findings[0]["finding"]
    assert "packages" in permission_findings[0]["finding"]


def test_read_only_and_empty_job_permissions_are_not_flagged():
    workflow = {
        "permissions": {"contents": "read"},
        "jobs": {
            "test": {"permissions": {"contents": "read"}, "steps": []},
            "isolated": {"permissions": {}, "steps": []},
        },
    }
    assert scan_workflow(workflow) == []


def test_unpinned_action_generates_finding():
    workflow = {"permissions": {"contents": "read"}, "jobs": {"test": {"steps": [{"uses": "actions/checkout@v4"}]}}}
    findings = scan_workflow(workflow)
    assert any("not pinned" in finding["finding"] for finding in findings)


def test_pinned_action_does_not_generate_action_finding():
    workflow = yaml.safe_load(
        """
        permissions:
          contents: read
        jobs:
          test:
            steps:
              - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332
        """
    )
    findings = scan_workflow(workflow)
    assert findings == []


def test_secret_pattern_generates_critical_finding():
    workflow = {"permissions": {"contents": "read"}, "jobs": {}}
    findings = scan_workflow(workflow, "api_key=ABCDEF1234567890")
    assert findings[0]["severity"] == "critical"


def test_remote_script_piped_to_shell_is_detected():
    workflow = {
        "permissions": {"contents": "read"},
        "jobs": {
            "build": {
                "steps": [
                    {"name": "Unsafe install", "run": "curl https://example.invalid/install.sh | sh"}
                ]
            }
        },
    }
    findings = scan_workflow(workflow)
    assert any("remote script piped to shell" in finding["finding"] for finding in findings)
    assert any(finding["severity"] == "high" for finding in findings)
