from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

from .scanner import scan_workflow


def main(workflow_path: str) -> None:
    raw_text = Path(workflow_path).read_text(encoding="utf-8")
    workflow = yaml.safe_load(raw_text)
    findings = scan_workflow(workflow, raw_text)
    print(json.dumps(findings, indent=2))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python -m cicd_guard.scan samples/workflows/insecure-workflow.yml")
    main(sys.argv[1])
