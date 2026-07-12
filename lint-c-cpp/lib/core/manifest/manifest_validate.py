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

"""Validate the consumer lint-c-cpp manifest shape.

Every allowed key must be present (use ``null`` when unused). Unknown keys fail.
Content rules still apply to non-null values (e.g. ``scan``, ``policy``, ``compile_db``).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

_LINT_LIB = Path(__file__).resolve().parents[2]
if str(_LINT_LIB) not in sys.path:
    sys.path.insert(0, str(_LINT_LIB))
from lint_pythonpath import bootstrap as _bootstrap_lint_pythonpath

_bootstrap_lint_pythonpath()

try:
    import yaml
except ImportError:
    yaml = None

from consumer_manifest import KNOWN_LINT_JOBS, load

ALLOWED_TOP_LEVEL_KEYS = frozenset(
    {
        "compile_db",
        "enabled_lint_jobs",
        "license_header",
        "policy",
        "scan",
        "spec_traceability",
        "toolchain",
        "workflow",
        "yamllint",
    }
)
REMOVED_TOP_LEVEL_KEYS = frozenset(
    {
        "clang_tidy",
        "format",
        "linters",
    }
)
# Non-null required: these drive lint. Others may be null.
REQUIRED_NONEMPTY_TOP_LEVEL = frozenset(
    {"compile_db", "enabled_lint_jobs", "license_header", "policy", "scan"}
)
ALLOWED_SCAN_KEYS = frozenset(
    {
        "c_api_prefix",
        "c_macro_prefix",
        "exclude_gitignore",
        "public_headers_dir",
        "source_roots",
    }
)


ALLOWED_COMPILE_DB_KEYS = frozenset(
    {"firmware", "userspace"}
)
ALLOWED_COMPILE_DB_FIRMWARE_ENTRY_KEYS = frozenset(
    {"compile_commands_json", "commands"}
)
ALLOWED_COMPILE_DB_USERSPACE_ENTRY_KEYS = frozenset(
    {"compile_commands_json", "source", "cmake_args"}
)


ALLOWED_POLICY_KEYS = frozenset(
    {
        "nolint_allowed",
        "overrides",
        "resource_lifetime",
        "shared_c_cxx_source_roots",
        "constants_headers",
        "unsafe_api",
    }
)
REMOVED_POLICY_KEYS = frozenset(
    {
        "bounds",
        "firmware_lint_exemptions",
        "headers",
    }
)
# Non-null required under policy.
REQUIRED_NONEMPTY_POLICY = frozenset({"constants_headers", "overrides", "unsafe_api"})
ALLOWED_RESOURCE_LIFETIME_KEYS = frozenset({"pairs"})
ALLOWED_WORKFLOW_KEYS = frozenset({"bare_vm_waivers"})
ALLOWED_WAIVER_ENTRY_KEYS = frozenset({"job", "workflow"})
ALLOWED_TOOLCHAIN_KEYS = frozenset({"lint_kit", "script"})
ALLOWED_LINT_KIT_KEYS = frozenset({"path", "ref", "repository"})
ALLOWED_SPEC_TRACEABILITY_KEYS = frozenset({"manifest"})
ALLOWED_YAMLLINT_KEYS = frozenset({"default", "files"})


def _unknown_keys(mapping: dict, allowed: frozenset[str], label: str) -> list[str]:
    unknown = sorted(key for key in mapping if key not in allowed)
    if not unknown:
        return []
    return [
        f"unknown {label}: {', '.join(unknown)} "
        f"(allowed: {', '.join(sorted(allowed))})"
    ]


def _missing_required_keys(
    mapping: dict,
    required: frozenset[str],
    label: str,
) -> list[str]:
    missing = sorted(key for key in required if key not in mapping)
    if not missing:
        return []
    return [
        f"{label} missing required keys: {', '.join(missing)} "
        "(declare every allowed key; use null if unused)"
    ]


def _require_mapping_keys(
    value: Any,
    *,
    allowed: frozenset[str],
    label: str,
    allow_null: bool,
) -> list[str]:
    """Require a mapping with every allowed key present (or null for the whole block)."""
    if value is None:
        if allow_null:
            return []
        return [f"{label} is required (use null if unused)"]
    if not isinstance(value, dict):
        return [f"{label} must be a mapping or null"]
    issues = _unknown_keys(value, allowed, f"{label} fields")
    issues.extend(_missing_required_keys(value, allowed, label))
    return issues



def validate_allowed_policy_keys(policy: dict, manifest_path: Path) -> list[str]:
    issues: list[str] = []
    removed = sorted(key for key in policy if key in REMOVED_POLICY_KEYS)
    if removed:
        issues.append(
            f"{manifest_path}: removed policy fields: {', '.join(removed)} "
            "(bounds/headers/firmware_lint_exemptions are kit-owned; rename C++ .h to .hpp)"
        )
    unknown = sorted(
        key for key in policy if key not in ALLOWED_POLICY_KEYS and key not in REMOVED_POLICY_KEYS
    )
    if unknown:
        issues.append(
            f"{manifest_path}: unknown policy fields: {', '.join(unknown)} "
            f"(allowed: {', '.join(sorted(ALLOWED_POLICY_KEYS))})"
        )
    issues.extend(
        f"{manifest_path}: {message}"
        for message in _missing_required_keys(policy, ALLOWED_POLICY_KEYS, "policy")
    )
    return issues


def validate_scan_block(scan: dict, manifest_path: Path) -> list[str]:
    issues: list[str] = []
    issues.extend(
        f"{manifest_path}: {message}"
        for message in _missing_required_keys(scan, ALLOWED_SCAN_KEYS, "scan")
    )
    raw_roots = scan.get("source_roots")
    if not isinstance(raw_roots, list) or not raw_roots:
        issues.append(f"{manifest_path}: scan.source_roots must be a non-empty list")
    elif not all(isinstance(item, str) and item.strip() for item in raw_roots):
        issues.append(f"{manifest_path}: scan.source_roots entries must be non-empty strings")
    for key, label in (
        ("c_api_prefix", "scan.c_api_prefix"),
        ("c_macro_prefix", "scan.c_macro_prefix"),
        ("public_headers_dir", "scan.public_headers_dir"),
    ):
        value = scan.get(key)
        if not isinstance(value, str) or not value.strip():
            issues.append(f"{manifest_path}: {label} must be a non-empty string")
    if "exclude_gitignore" in scan and not isinstance(scan.get("exclude_gitignore"), bool):
        issues.append(f"{manifest_path}: scan.exclude_gitignore must be a boolean")
    return issues


def validate_allowed_top_level_keys(data: dict, manifest_path: Path) -> list[str]:
    issues: list[str] = []
    removed = sorted(key for key in data if key in REMOVED_TOP_LEVEL_KEYS)
    if removed:
        issues.append(
            f"{manifest_path}: removed top-level fields: {', '.join(removed)} "
            "(use policy.overrides for clang-format/clang-tidy dials)"
        )
    unknown = sorted(
        key
        for key in data
        if key not in ALLOWED_TOP_LEVEL_KEYS and key not in REMOVED_TOP_LEVEL_KEYS
    )
    if unknown:
        issues.append(f"{manifest_path}: unknown top-level fields: {', '.join(unknown)}")
    missing = sorted(key for key in ALLOWED_TOP_LEVEL_KEYS if key not in data)
    if missing:
        issues.append(
            f"{manifest_path}: missing required top-level keys: {', '.join(missing)} "
            "(declare every allowed key; use null if unused)"
        )
    for key in REQUIRED_NONEMPTY_TOP_LEVEL:
        if key not in data:
            continue
        if data.get(key) is None:
            issues.append(f"{manifest_path}: {key} must not be null")
    return issues


def validate_enabled_lint_jobs(data: dict, manifest_path: Path) -> list[str]:
    raw = data.get("enabled_lint_jobs")
    if raw is None:
        return []
    if not isinstance(raw, list):
        return [f"{manifest_path}: enabled_lint_jobs must be a non-empty list of job IDs"]
    if not raw:
        return [
            f"{manifest_path}: enabled_lint_jobs must be non-empty "
            "(list every job to run; omit a job to disable it)"
        ]
    issues: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(raw):
        if not isinstance(item, str) or not item.strip():
            issues.append(
                f"{manifest_path}: enabled_lint_jobs[{index}] must be a non-empty string"
            )
            continue
        job = item.strip()
        if job not in KNOWN_LINT_JOBS:
            issues.append(
                f"{manifest_path}: enabled_lint_jobs[{index}]: unknown job {job!r} "
                f"(known: {', '.join(sorted(KNOWN_LINT_JOBS))})"
            )
            continue
        if job in seen:
            issues.append(f"{manifest_path}: enabled_lint_jobs: duplicate job {job!r}")
            continue
        seen.add(job)
    return issues


def validate_allowed_scan_keys(scan: dict, manifest_path: Path) -> list[str]:
    issues = _unknown_keys(scan, ALLOWED_SCAN_KEYS, "scan fields")
    return [f"{manifest_path}: {message}" for message in issues]


def validate_resource_lifetime_regexes(data: dict, manifest_path: Path) -> list[str]:
    import re

    policy = data.get("policy")
    if not isinstance(policy, dict):
        return []
    block = policy.get("resource_lifetime")
    if block is None:
        return []
    issues = [
        f"{manifest_path}: {message}"
        for message in _require_mapping_keys(
            block,
            allowed=ALLOWED_RESOURCE_LIFETIME_KEYS,
            label="policy.resource_lifetime",
            allow_null=False,
        )
    ]
    if not isinstance(block, dict):
        return issues
    pairs = block.get("pairs")
    if pairs is None:
        return issues
    if not isinstance(pairs, list):
        issues.append(f"{manifest_path}: policy.resource_lifetime.pairs must be a list or null")
        return issues
    for index, pair in enumerate(pairs):
        if not isinstance(pair, dict):
            continue
        label = str(pair.get("label") or f"pair[{index}]")
        for field in ("acquire", "release"):
            raw = pair.get(field, [])
            if not isinstance(raw, list):
                issues.append(f"{manifest_path}: policy.resource_lifetime.pairs[{index}].{field} must be a list")
                continue
            for pattern in raw:
                if not isinstance(pattern, str):
                    continue
                try:
                    re.compile(pattern)
                except re.error as exc:
                    issues.append(
                        f"{manifest_path}: policy.resource_lifetime {label} {field} pattern {pattern!r}: {exc}"
                    )
    return issues


def validate_workflow_waivers(data: dict, manifest_path: Path) -> list[str]:
    workflow = data.get("workflow")
    if workflow is None:
        return []
    issues = [
        f"{manifest_path}: {message}"
        for message in _require_mapping_keys(
            workflow,
            allowed=ALLOWED_WORKFLOW_KEYS,
            label="workflow",
            allow_null=False,
        )
    ]
    if not isinstance(workflow, dict):
        return issues
    raw = workflow.get("bare_vm_waivers")
    if raw is None:
        return issues
    if not isinstance(raw, list):
        issues.append(f"{manifest_path}: workflow.bare_vm_waivers must be a list or null")
        return issues
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            issues.append(f"{manifest_path}: workflow.bare_vm_waivers[{index}] must be a mapping")
            continue
        issues.extend(
            f"{manifest_path}: {message}"
            for message in _unknown_keys(
                item,
                ALLOWED_WAIVER_ENTRY_KEYS,
                f"workflow.bare_vm_waivers[{index}] fields",
            )
        )
        issues.extend(
            f"{manifest_path}: {message}"
            for message in _missing_required_keys(
                item,
                ALLOWED_WAIVER_ENTRY_KEYS,
                f"workflow.bare_vm_waivers[{index}]",
            )
        )
        job = item.get("job")
        if isinstance(job, str) and job.strip().casefold() == "lint":
            workflow_file = item.get("workflow") or "?"
            issues.append(
                f"{manifest_path}: workflow.bare_vm_waivers[{index}] must not waive lint jobs "
                f"({workflow_file}); lint jobs must always use container:"
            )
    return issues


def validate_optional_top_level_sections(data: dict, manifest_path: Path) -> list[str]:
    issues: list[str] = []
    toolchain = data.get("toolchain")
    issues.extend(
        f"{manifest_path}: {message}"
        for message in _require_mapping_keys(
            toolchain,
            allowed=ALLOWED_TOOLCHAIN_KEYS,
            label="toolchain",
            allow_null=True,
        )
    )
    if isinstance(toolchain, dict):
        lint_kit = toolchain.get("lint_kit")
        issues.extend(
            f"{manifest_path}: {message}"
            for message in _require_mapping_keys(
                lint_kit,
                allowed=ALLOWED_LINT_KIT_KEYS,
                label="toolchain.lint_kit",
                allow_null=True,
            )
        )
        script = toolchain.get("script")
        if script is not None and (not isinstance(script, str) or not script.strip()):
            issues.append(f"{manifest_path}: toolchain.script must be a non-empty string or null")

    spec_traceability = data.get("spec_traceability")
    issues.extend(
        f"{manifest_path}: {message}"
        for message in _require_mapping_keys(
            spec_traceability,
            allowed=ALLOWED_SPEC_TRACEABILITY_KEYS,
            label="spec_traceability",
            allow_null=True,
        )
    )
    if isinstance(spec_traceability, dict):
        manifest_rel = spec_traceability.get("manifest")
        if manifest_rel is not None and (
            not isinstance(manifest_rel, str) or not manifest_rel.strip()
        ):
            issues.append(
                f"{manifest_path}: spec_traceability.manifest must be a non-empty string or null"
            )

    yamllint = data.get("yamllint")
    issues.extend(
        f"{manifest_path}: {message}"
        for message in _require_mapping_keys(
            yamllint,
            allowed=ALLOWED_YAMLLINT_KEYS,
            label="yamllint",
            allow_null=True,
        )
    )
    return issues


def validate_policy(data: dict, manifest_path: Path) -> list[str]:
    policy = data.get("policy")
    if not isinstance(policy, dict):
        return [f"{manifest_path}: policy must be a mapping"]
    issues: list[str] = []
    issues.extend(validate_allowed_policy_keys(policy, manifest_path))
    for key in REQUIRED_NONEMPTY_POLICY:
        if key in policy and policy.get(key) is None:
            issues.append(f"{manifest_path}: policy.{key} must not be null")

    raw_shared = policy.get("constants_headers")
    if not isinstance(raw_shared, list) or not raw_shared:
        issues.append(f"{manifest_path}: policy.constants_headers must be a non-empty list")
    elif not all(isinstance(item, str) and item.strip() for item in raw_shared):
        issues.append(f"{manifest_path}: policy.constants_headers entries must be non-empty strings")

    raw_nolint = policy.get("nolint_allowed")
    if raw_nolint is not None:
        if not isinstance(raw_nolint, list) or not raw_nolint:
            issues.append(
                f"{manifest_path}: policy.nolint_allowed must be a non-empty list or null"
            )
        elif not all(isinstance(item, str) and item.strip() for item in raw_nolint):
            issues.append(f"{manifest_path}: policy.nolint_allowed entries must be non-empty strings")

    shared_c_cxx = policy.get("shared_c_cxx_source_roots")
    if shared_c_cxx is not None:
        if (
            not isinstance(shared_c_cxx, list)
            or not shared_c_cxx
            or not all(isinstance(item, str) and item.strip() for item in shared_c_cxx)
        ):
            issues.append(
                f"{manifest_path}: policy.shared_c_cxx_source_roots must be a "
                "non-empty list of non-empty strings or null"
            )

    resource_lifetime = policy.get("resource_lifetime")
    issues.extend(
        f"{manifest_path}: {message}"
        for message in _require_mapping_keys(
            resource_lifetime,
            allowed=ALLOWED_RESOURCE_LIFETIME_KEYS,
            label="policy.resource_lifetime",
            allow_null=True,
        )
    )
    return issues


def validate_overrides(data: dict, manifest_path: Path, repo_root: Path) -> list[str]:
    from policy_overrides import validate_policy_overrides

    return validate_policy_overrides(data, manifest_path, repo_root)


ALLOWED_UNSAFE_API_KEYS = frozenset(
    {
        "header",
        "include_headers",
        "wrapper_files",
    }
)


def validate_unsafe_api(data: dict, manifest_path: Path) -> list[str]:
    policy = data.get("policy")
    if not isinstance(policy, dict):
        return []
    block = policy.get("unsafe_api")
    if not isinstance(block, dict):
        return [f"{manifest_path}: policy.unsafe_api must be a mapping"]
    issues: list[str] = []
    unknown = sorted(key for key in block if key not in ALLOWED_UNSAFE_API_KEYS)
    if unknown:
        issues.append(
            f"{manifest_path}: unknown policy.unsafe_api fields: {', '.join(unknown)}"
        )
    header = block.get("header")
    if not isinstance(header, str) or not header.strip():
        issues.append(f"{manifest_path}: policy.unsafe_api.header must be a non-empty string")
    include_headers = block.get("include_headers")
    if not isinstance(include_headers, list) or not include_headers:
        issues.append(f"{manifest_path}: policy.unsafe_api.include_headers must be a non-empty list")
    elif not all(isinstance(item, str) and item.strip() for item in include_headers):
        issues.append(f"{manifest_path}: policy.unsafe_api.include_headers entries must be non-empty strings")
    raw = block.get("wrapper_files")
    if not isinstance(raw, list) or not raw:
        issues.append(f"{manifest_path}: policy.unsafe_api.wrapper_files must be a non-empty list")
    elif not all(isinstance(item, str) and item.strip() for item in raw):
        issues.append(f"{manifest_path}: policy.unsafe_api.wrapper_files entries must be non-empty strings")
    return issues


def _validate_compile_db_firmware_list(firmware: Any, manifest_path: Path) -> list[str]:
    issues: list[str] = []
    if isinstance(firmware, dict):
        issues.append(
            f"{manifest_path}: compile_db.firmware must be a list "
            "(use `- compile_commands_json: …` entries)"
        )
        return issues
    if not isinstance(firmware, list) or not firmware:
        issues.append(f"{manifest_path}: compile_db.firmware must be a non-empty list")
        return issues
    for index, entry in enumerate(firmware):
        label = f"compile_db.firmware[{index}]"
        if not isinstance(entry, dict):
            issues.append(f"{manifest_path}: {label} must be a mapping")
            continue
        entry_unknown = sorted(
            key for key in entry if key not in ALLOWED_COMPILE_DB_FIRMWARE_ENTRY_KEYS
        )
        if entry_unknown:
            issues.append(f"{manifest_path}: unknown {label} fields: {', '.join(entry_unknown)}")
        compile_db = entry.get("compile_commands_json")
        if compile_db is None:
            issues.append(f"{manifest_path}: {label}.compile_commands_json is required")
        elif not isinstance(compile_db, str) or not compile_db.strip():
            issues.append(
                f"{manifest_path}: {label}.compile_commands_json must be a non-empty string"
            )
        commands = entry.get("commands")
        if commands is None:
            issues.append(f"{manifest_path}: {label}.commands is required")
        elif not isinstance(commands, list) or not commands:
            issues.append(f"{manifest_path}: {label}.commands must be a non-empty list")
        elif not all(isinstance(item, str) and item.strip() for item in commands):
            issues.append(
                f"{manifest_path}: {label}.commands entries must be non-empty strings"
            )
    return issues


def _validate_compile_db_userspace_list(userspace: Any, manifest_path: Path) -> list[str]:
    issues: list[str] = []
    if isinstance(userspace, dict):
        issues.append(
            f"{manifest_path}: compile_db.userspace must be a list "
            "(use `- compile_commands_json: …` entries)"
        )
        return issues
    if not isinstance(userspace, list) or not userspace:
        issues.append(f"{manifest_path}: compile_db.userspace must be a non-empty list")
        return issues
    for index, entry in enumerate(userspace):
        label = f"compile_db.userspace[{index}]"
        if not isinstance(entry, dict):
            issues.append(f"{manifest_path}: {label} must be a mapping")
            continue
        entry_unknown = sorted(
            key for key in entry if key not in ALLOWED_COMPILE_DB_USERSPACE_ENTRY_KEYS
        )
        if entry_unknown:
            issues.append(f"{manifest_path}: unknown {label} fields: {', '.join(entry_unknown)}")
        issues.extend(
            f"{manifest_path}: {message}"
            for message in _missing_required_keys(
                entry, ALLOWED_COMPILE_DB_USERSPACE_ENTRY_KEYS, label
            )
        )
        compile_db = entry.get("compile_commands_json")
        if compile_db is None:
            issues.append(f"{manifest_path}: {label}.compile_commands_json is required")
        elif not isinstance(compile_db, str) or not compile_db.strip():
            issues.append(
                f"{manifest_path}: {label}.compile_commands_json must be a non-empty string"
            )
        source = entry.get("source")
        if source is None:
            issues.append(f"{manifest_path}: {label}.source is required")
        elif not isinstance(source, str) or not source.strip():
            issues.append(f"{manifest_path}: {label}.source must be a non-empty string")
        cmake_args = entry.get("cmake_args")
        if cmake_args is not None and (
            not isinstance(cmake_args, list)
            or not all(isinstance(item, str) and item.strip() for item in cmake_args)
        ):
            issues.append(
                f"{manifest_path}: {label}.cmake_args must be a list of non-empty strings or null"
            )
    return issues


def validate_compile_db(data: dict, manifest_path: Path) -> list[str]:
    block = data.get("compile_db")
    if block is None:
        return [
            f"{manifest_path}: compile_db is required — declare compile_db.firmware and "
            "compile_db.userspace so the lint proves the code compiles (no silent skip)"
        ]
    if not isinstance(block, dict):
        return [f"{manifest_path}: compile_db must be a mapping"]
    issues: list[str] = []
    unknown = sorted(key for key in block if key not in ALLOWED_COMPILE_DB_KEYS)
    if unknown:
        issues.append(f"{manifest_path}: unknown compile_db fields: {', '.join(unknown)}")
    firmware = block.get("firmware")
    if firmware is None:
        issues.append(f"{manifest_path}: compile_db.firmware is required")
    else:
        issues.extend(_validate_compile_db_firmware_list(firmware, manifest_path))
    userspace = block.get("userspace")
    if userspace is None:
        issues.append(f"{manifest_path}: compile_db.userspace is required")
    else:
        issues.extend(_validate_compile_db_userspace_list(userspace, manifest_path))
    return issues


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    repo = args.repo_root.resolve()
    manifest = repo / ".github" / "lint-c-cpp.yaml"
    if not manifest.is_file():
        print(f"error: missing consumer lint manifest: {manifest}", file=sys.stderr)
        return 1
    text = manifest.read_text(encoding="utf-8")
    required = ("scan:", "c_api_prefix:", "c_macro_prefix:", "public_headers_dir:")
    missing = [field for field in required if field not in text]
    if missing:
        print(f"error: {manifest} missing fields: {', '.join(missing)}", file=sys.stderr)
        return 1
    if yaml is None:
        print("error: PyYAML is required to validate .github/lint-c-cpp.yaml", file=sys.stderr)
        return 2
    try:
        load(repo, required=True)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    data = yaml.safe_load(text) or {}
    if not isinstance(data, dict):
        print(f"error: {manifest} must be a mapping at top level", file=sys.stderr)
        return 1

    issues: list[str] = []
    license_header = data.get("license_header")
    if not isinstance(license_header, str) or not license_header.strip():
        issues.append(
            f"{manifest}: license_header must be a non-empty string (block scalar)"
        )
    issues.extend(validate_allowed_top_level_keys(data, manifest))
    issues.extend(validate_enabled_lint_jobs(data, manifest))
    scan = data.get("scan")
    if not isinstance(scan, dict):
        print(f"error: {manifest} scan must be a mapping", file=sys.stderr)
        return 1
    issues.extend(validate_allowed_scan_keys(scan, manifest))
    issues.extend(validate_scan_block(scan, manifest))

    issues.extend(validate_policy(data, manifest))
    issues.extend(validate_overrides(data, manifest, repo))
    issues.extend(validate_unsafe_api(data, manifest))
    issues.extend(validate_resource_lifetime_regexes(data, manifest))
    issues.extend(validate_workflow_waivers(data, manifest))
    issues.extend(validate_optional_top_level_sections(data, manifest))
    issues.extend(validate_compile_db(data, manifest))
    if isinstance(data.get("compile_db"), dict):
        from consumer_manifest import compile_db_cmake_coverage_issues

        for issue in compile_db_cmake_coverage_issues(repo):
            issues.append(f"{manifest}: {issue}")
    if issues:
        for issue in issues:
            print(f"error: {issue}", file=sys.stderr)
        return 1
    print(f"validate_manifest: OK — {manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
