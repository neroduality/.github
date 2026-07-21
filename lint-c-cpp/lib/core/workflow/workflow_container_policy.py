#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2026 Nero Duality, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Validate GitHub Actions workflows for container policy."""
from __future__ import annotations

import argparse
import sys
from itertools import chain
from pathlib import Path

_LINT_LIB = Path(__file__).resolve().parents[2]
if str(_LINT_LIB) not in sys.path:
    sys.path.insert(0, str(_LINT_LIB))
from lint_pythonpath import bootstrap as _bootstrap_lint_pythonpath

_bootstrap_lint_pythonpath()

try:
    import yaml
except ImportError:
    print("error: PyYAML is required for workflow lint", file=sys.stderr)
    raise SystemExit(2) from None

from consumer_manifest import workflow_bare_vm_waivers


def valid_container(value: object) -> bool:
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, dict):
        image = value.get("image")
        return isinstance(image, str) and bool(image.strip())
    return False


def lint_workflows(repo_root: Path) -> int:
    workflow_dir = repo_root / ".github" / "workflows"
    waivers = workflow_bare_vm_waivers(repo_root)
    errors: list[str] = []

    workflow_files = sorted(chain(workflow_dir.glob("*.yml"), workflow_dir.glob("*.yaml")))
    if not workflow_files:
        errors.append(f"{workflow_dir}: no workflow files found")

    for workflow in workflow_files:
        rel = workflow.relative_to(repo_root)
        try:
            data = yaml.safe_load(workflow.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            errors.append(f"{rel}: invalid YAML: {exc}")
            continue
        if not isinstance(data, dict):
            errors.append(f"{rel}: workflow root must be a mapping")
            continue
        jobs = data.get("jobs")
        if not isinstance(jobs, dict) or not jobs:
            errors.append(f"{rel}: jobs must be a non-empty mapping")
            continue
        for job_id, job in jobs.items():
            if not isinstance(job, dict):
                errors.append(f"{rel}:{job_id}: job must be a mapping")
                continue
            has_run_step = any(
                isinstance(step, dict) and "run" in step for step in job.get("steps", [])
            )
            if has_run_step and not valid_container(job.get("container")):
                waiver_key = (workflow.name, str(job_id))
                if str(job_id).casefold() == "lint":
                    errors.append(
                        f"{rel}:{job_id}: lint job must declare container: "
                        "(bare-VM waivers are not allowed for lint)"
                    )
                    continue
                if waiver_key in waivers:
                    print(f"waive: {workflow.name}:{job_id} bare-VM run-step job")
                    continue
                errors.append(
                    f"{rel}:{job_id}: run-step job must declare container: or a "
                    "workflow.bare_vm_waivers entry (lint jobs must always declare "
                    "container: and cannot be waived)"
                )

    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1

    print(f"workflow-lint: OK ({len(workflow_files)} workflow files)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    return lint_workflows(args.repo_root.resolve())


if __name__ == "__main__":
    raise SystemExit(main())
