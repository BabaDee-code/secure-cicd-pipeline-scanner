import yaml

from cicd_guard.scanner import scan_workflow


def test_write_all_permissions_generate_high_finding():
    workflow = {"permissions": "write-all", "jobs": {}}
    findings = scan_workflow(workflow)
    assert findings[0]["severity"] == "high"
    assert "write-all" in findings[0]["finding"]


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


def test_pull_request_target_checkout_of_pr_head_is_critical():
    workflow = {
        "on": {"pull_request_target": {}},
        "permissions": {"contents": "read"},
        "jobs": {
            "review": {
                "steps": [
                    {
                        "uses": "actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332",
                        "with": {"ref": "${{ github.event.pull_request.head.sha }}"},
                    }
                ]
            }
        },
    }
    findings = scan_workflow(workflow)
    assert any("checks out untrusted pull request code" in finding["finding"] for finding in findings)
    assert any(finding["severity"] == "critical" for finding in findings)


def test_pull_request_target_checkout_of_trusted_base_is_not_flagged():
    workflow = {
        "on": {"pull_request_target": {}},
        "permissions": {"contents": "read"},
        "jobs": {
            "review": {
                "steps": [
                    {"uses": "actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332"}
                ]
            }
        },
    }
    findings = scan_workflow(workflow)
    assert not any("checks out untrusted pull request code" in finding["finding"] for finding in findings)


def test_direct_pr_title_interpolation_in_run_is_high_risk():
    workflow = {
        "on": {"pull_request": {}},
        "permissions": {"contents": "read"},
        "jobs": {
            "lint": {
                "steps": [
                    {"run": 'echo "PR: ${{ github.event.pull_request.title }}"'}
                ]
            }
        },
    }
    findings = scan_workflow(workflow)
    assert any("metadata is interpolated directly" in finding["finding"] for finding in findings)
    assert any(finding["severity"] == "high" for finding in findings)


def test_pr_title_passed_via_env_is_not_direct_interpolation():
    workflow = {
        "on": {"pull_request": {}},
        "permissions": {"contents": "read"},
        "jobs": {
            "lint": {
                "steps": [
                    {
                        "env": {"PR_TITLE": "${{ github.event.pull_request.title }}"},
                        "run": 'printf "%s\\n" "$PR_TITLE"',
                    }
                ]
            }
        },
    }
    findings = scan_workflow(workflow)
    assert not any("metadata is interpolated directly" in finding["finding"] for finding in findings)


def test_pyyaml_boolean_on_key_is_supported_for_pull_request_target_detection():
    workflow = yaml.safe_load(
        """
        on:
          pull_request_target:
        permissions:
          contents: read
        jobs:
          review:
            steps:
              - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332
                with:
                  ref: ${{ github.event.pull_request.head.ref }}
        """
    )
    findings = scan_workflow(workflow)
    assert any("checks out untrusted pull request code" in finding["finding"] for finding in findings)
